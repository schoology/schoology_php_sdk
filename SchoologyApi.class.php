<?php

class SchoologyApi
{
  private $_consumer_key;
  private $_consumer_secret;
  private $_token_key = '';
  private $_token_secret = '';
  private $_is_two_legged = '';

  private $_api_supported_methods = array('POST','GET','PUT','DELETE','OPTIONS');
  private $_api_base = '';
  private $_api_site_base = '';
  
  private $_saml_cert_path;

  private $curl_resource;
  private $curl_opts = array(
    CURLOPT_USERAGENT => 'schoology-php-1.0',
    CURLOPT_CONNECTTIMEOUT => 20,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 60,
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_HEADER => TRUE,
  // Each request needs a new nonce, so the same 
  // header can't be used to follow redirects
    CURLOPT_FOLLOWLOCATION => FALSE, 
    CURLOPT_COOKIESESSION => FALSE,
  );



  public function __construct( $consumer_key, $consumer_secret, $site_base = '', $token_key = '', $token_secret = '', $two_legged = FALSE)
  {
    $this->_api_base = defined('SCHOOLOGY_API_BASE') ? SCHOOLOGY_API_BASE : 'http://api.schoology.com/v1';
    if($site_base) {
      $this->_api_site_base = $site_base;
    }
    else {
      $this->_api_site_base = defined('SCHOOLOGY_API_BASE') ? SCHOOLOGY_SITE_BASE : 'https://www.schoology.com';
    }
    $this->_consumer_key = $consumer_key;
    $this->_consumer_secret = $consumer_secret;
    // If you don't want to use this class's OAuth verification
    // management, you can do so yourself and pass in an 
    // access key and access secret. Otherwise, leave blank.
    if($token_key && $token_secret){
      $this->_token_key = $token_key;
      $this->_token_secret = $token_secret;
    }
    
    $this->curl_resource = curl_init();
    $this->_is_two_legged = $two_legged;
    $this->_saml_cert_path = __DIR__ . '/app.schoology.com.crt';
  }
  
  public function __destruct(){
    curl_close($this->curl_resource);
  }
  
  /**
   * Identify the user through SAML
   */
  public function validateLogin(){
    // Load SAML libraries
    require_once __DIR__.'/phpsaml/Sperantus/SAML2/SP/Response.php';
    // Check if we are receiving a SAML response
    if (isset($_REQUEST['SAMLResponse'])) { // allow either $_GET or $_POST
      // This object decodes & gives access to SAML Response attributes & name id
      $cert = file_get_contents($this->_saml_cert_path);
      $samlresponse = new Sperantus_SAML2_SP_Response($cert, $_POST['SAMLResponse']);
      return array(
        'uid' => $samlresponse->getAttribute('uid'),
        'name_display' => $samlresponse->getAttribute('name_display'),
        'school_nid' => $samlresponse->getAttribute('school_nid'),
        'school_title' => $samlresponse->getAttribute('school_title'),
        'role_id' => $samlresponse->getAttribute('role_id'),
        'is_admin' => $samlresponse->getAttribute('is_admin'),
        'timezone_name' => $samlresponse->getAttribute('timezone_name'),
        'domain' => $samlresponse->getAttribute('domain'),
      );
    }
    else {
      // Here, a normal SAML application would initiate an authentication
      // request, but Schoology apps should only be authenticated from
      // Schoology (not vice versa). If a user is somehow logged out of
      // the application, they should reload the app within Schoology
      // to re-initiate authentication. 
    }
    
    return FALSE;
  }
  
  /**
  * Create a valid SAML logout response
  * Based off of Sperantus_SAML2_SP_AuthRequest
  */
  public function logoutResponseUrl($logoutRequest, $returnUrl){
    $id = uniqid('',true);
    $issueInstant = date('Y-m-d\TH:i:s\Z');
    $issuer = $this->_token_key;
    
    $response = @gzinflate(base64_decode($logoutRequest));
    if(!strlen($response)){
      return FALSE;
    }
    $matches = array();
    preg_match('/ID=\"(.+?)\"/', $response, $matches);
    if(!isset($matches[1])){
      return FALSE;
    }
    $responseTo = $matches[1];
    $request = '
      <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
          ID="'.$id.'" Version="2.0" IssueInstant="'.$issueInstant.'"
          InResponseTo="'.$responseTo.'">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'.$issuer.'</saml:Issuer>
          <samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
              <samlp:StatusCode  
                   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                   Value="urn:oasis:names:tc:SAML:2.0:status:Success">
              </samlp:StatusCode>
         </samlp:Status>
       </samlp:LogoutResponse>';
    return $returnUrl.'?entityid='.urlencode($this->_consumer_key).'&SAMLResponse='.urlencode(base64_encode(gzdeflate($request))); 
  }
  
  /**
   * Initialize and set the proper access tokens for the 
   * user ID from the given storage engine
   */
  public function authorize(SchoologyApi_OauthStorage $storage, $uid, $app_session_timestamp){
    // Get stored access tokens for the given user ID
    $access_tokens = $storage->getAccessTokens($uid);
    // Access tokens were found - set them for API requests

    $get_new_tokens = FALSE;
    if($access_tokens){
      $this->_token_key = $access_tokens['token_key'];
      $this->_token_secret = $access_tokens['token_secret'];
      
      // Check to make sure a request works
      try {
        $web_session_info = $this->apiResult('app-user-info');
      
        if($web_session_info->api_uid != $uid){        
          $this->deauthorize($storage, $uid);
          $this->_token_key = '';
          $this->_token_secret = '';
          $get_new_tokens = TRUE;
        }
      } catch (Exception $e) {
        $bad_http_codes = array(400,401,403,404);
        // Something's wrong with the access tokens we have. Revoke them.
        if(in_array($e->getCode(), $bad_http_codes)) {     
          $this->deauthorize($storage, $uid);
          $this->_token_key = '';
          $this->_token_secret = '';
          $get_new_tokens = TRUE;
        }
      }

      // User does not have a web session or the sgy session is after the apps session - no reason to be using the app. The user needs to logout
      if(!$get_new_tokens && (!$web_session_info->web_session_timestamp || $web_session_info->web_session_timestamp > $app_session_timestamp)){
        throw new ExpiredSGYWebSession();
      }

    }
    else {
      $get_new_tokens = TRUE;
    }
    
    
    // Go through OAuth authentication
    if($get_new_tokens){
      $this->_authenticateOauth($storage, $uid);
    }
  }
  
  /**
   * Deauthorize a user and purge existing tokens (e.g. if tokens are no longer valid)
   */
  public function deauthorize(SchoologyApi_OauthStorage $storage, $uid){
    $storage->revokeAccessTokens($uid);
  }
  
  /**
   * Wrapper for api function below that only returns the relevant result
   */
  public function apiResult($url , $method = 'GET', $body = array(), $extra_headers = array()){
    static $redirects = 0;
    static $result;
    $result = $this->api($url, $method, $body, $extra_headers);

    $redirect_codes = array(301,302,303,305,307);
    if (in_array($result->http_code, $redirect_codes) && $redirects < 5 ){
      $redirects++;
      $redirect = parse_url($result->headers['Location']);
      $redirect_url = ltrim($redirect['path'], '/v1/');
      $this->apiResult($redirect_url);
    }
    //reset redirect count
    $redirects = 0;
    return $result->result;
  }

  /**
   * Make a schoology API Call
   */
  public function api( $url , $method = 'GET' , $body = array() , $extra_headers = array() )
  {
    if(!in_array($method,$this->_api_supported_methods))
      throw new Exception('API method '.$method.' is not supported. Must be '.implode(',',$this->_api_supported_methods));

    $api_url = $this->_api_base . '/' . ltrim($url,'/');
    
    // add the oauth headers
    $extra_headers[] = 'Authorization: '.$this->_makeOauthHeaders( $api_url , $method , $body );

    $response = $this->_curlRequest( $api_url , $method , $body , $extra_headers );

    // Something's gone wrong
    if($response->http_code > 400){
      throw new Exception($response->raw_result, $response->http_code);
    }

    return $response;
  }
  
  
  /**
  * Upload a file to Schoology servers
  * The file upload is a 2 step process.
  * 1) Aquire permission and a unique upload endpoint
  * 2) PUT the contents of the file to the endpoint from step 2
  *
  * @param string $filepath file path
  * @return
  * Upload id
  */
  public function apiFileUpload($filepath)
  {
    // step 1: set empty placeholder and get unique upload enpoint
    $filename = basename($filepath);
    $filesize = filesize($filepath);
    $md5_checksum = md5_file($filepath);
  
    $url = 'upload';
    $method = 'POST';
    $body = array(
      'filename' => $filename,
      'filesize' => $filesize,
      'md5_checksum' => $md5_checksum
    );
    $api_result = $this->api($url, $method, $body);
  
    // step2: PUT contents of file to enpoint above
    $fid = $api_result->result->id;
    $url = $api_result->result->upload_location;
    $headers = array(
      'Accept: application/json',
      'Connection: keep-alive',
      'Keep-Alive: 300',
      'Authorization: '. $this->_makeOauthHeaders( $url , 'PUT')
     );
    $fp = fopen($filepath, 'r');
  
    $curl_resource = curl_init();
      curl_setopt($curl_resource, CURLOPT_URL, $url);
      curl_setopt($curl_resource, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($curl_resource, CURLOPT_HTTPHEADER, $headers);
      curl_setopt($curl_resource, CURLOPT_PUT, TRUE);
      curl_setopt($curl_resource, CURLOPT_INFILE, $fp);
      curl_setopt($curl_resource, CURLOPT_INFILESIZE, $filesize);
    $result = curl_exec($curl_resource);
  
    if ($result === false) {
      throw new Exception('cURL execution failed');
    }
    
    $response = $this->_getApiResponse($curl_resource, $result);
    curl_close($curl_resource);
  
    if ($response->http_code !== 204) {
      throw new Exception('cURL execution failed');
    }
    
    return $fid;
  }
  
  private function _curlRequest($url = '', $method = '' , $body = array() , $extra_headers = array() )
  {
    $curl_resource = $this->curl_resource;
  
    $curl_options = $this->curl_opts;
    $curl_options[ CURLOPT_URL ] = $url;
  
    switch($method){
      case 'POST': 
        $curl_options[ CURLOPT_POST ] = TRUE; 
        $curl_options[ CURLOPT_CUSTOMREQUEST ] = 'POST';
        break;
      case 'PUT': 
        $curl_options[ CURLOPT_CUSTOMREQUEST ] = 'PUT'; 
        break;
      case 'DELETE': 
        $curl_options[ CURLOPT_CUSTOMREQUEST ] = 'DELETE'; 
        break;
      case 'GET': 
        $curl_options[ CURLOPT_HTTPGET ] = TRUE; 
        $curl_options[ CURLOPT_CUSTOMREQUEST ] = 'GET';
        break;
    }
  
    if(in_array($method,array('POST','PUT')) && !empty($body))
    {
      if(is_array($body ))
      $json_body = json_encode( $body );
  
      $curl_options[ CURLOPT_POSTFIELDS ] = $json_body;
    }
    $content_length = isset($json_body) ? strlen($json_body) : '0';

    $http_headers = array(
       'Accept: application/json',
       'Content-Type: application/json',
       'Content-Length: ' . $content_length
    );
  
    $curl_headers = array_merge( $http_headers , $extra_headers );
    $curl_options[ CURLOPT_HTTPHEADER ] = $curl_headers;

    curl_setopt_array( $curl_resource , $curl_options );

    $result = curl_exec($curl_resource);


    if ($result === false ) {
      throw new Exception('cURL execution failed');
    }
  
    return $this->_getApiResponse($curl_resource, $result);
  }
  
  private function _authenticateOauth($storage, $uid){
    // Get and authorize a request token
    if(!isset($_GET['oauth_token'])){
    
      // Get a request token
      $api_result = $this->api('/oauth/request_token');
    
      // Parse the query-string-formatted result
      $result = array();
      parse_str($api_result->result, $result);

      // Store the request token in our DB
      $storage->saveRequestTokens($uid, $result['oauth_token'], $result['oauth_token_secret']);

      // Now that we have a request token, forward the user to approve it
      $params = array(
              'return_url=' . urlencode('https://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']),
              'oauth_token=' . urlencode($result['oauth_token']),
      );
      $query_string = implode('&', $params);
      header('Location: ' . $this->_api_site_base . '/oauth/authorize?'  . $query_string);
      exit;
    }
    // The user has approved the token and returned to this page
    else {
      // Get the existing record from our DB
      $request_tokens = $storage->getRequestTokens($uid);

      // If the token doesn't match what we have in the DB, someone's tampering with requests
      if($request_tokens['token_key'] !== $_GET['oauth_token']){
        throw new Exception('Invalid oauth_token received.');
      }
    
      // Request access tokens using our newly approved request tokens
      $this->_token_key = $request_tokens['token_key'];
      $this->_token_secret = $request_tokens['token_secret'];
      $api_result = $this->api('/oauth/access_token');
    
      // Parse the query-string-formatted result
      $result = array();
      parse_str($api_result->result, $result);
    
      // Update our DB to replace the request tokens with access tokens
      $storage->requestToAccessTokens($uid, $result['oauth_token'], $result['oauth_token_secret']);
    
      // Update our $oauth credentials and proceed normally
      $this->_token_key = $result['oauth_token'];
      $this->_token_secret = $result['oauth_token_secret'];
    }
  }

  private function _makeOauthHeaders( $url = '' , $method = '' , $body = '' )
  {
    $timestamp = time();

    $nonce = uniqid();

    $oauth_config = array(
     'oauth_consumer_key' => $this->_consumer_key,
     'oauth_nonce' => $nonce,
     'oauth_signature_method' => 'HMAC-SHA1',
     'oauth_timestamp' => $timestamp,
     'oauth_token' => $this->_token_key,
     'oauth_version' => '1.0',
    );
    if ($this->_is_two_legged){
     $oauth_config['oauth_signature_method'] = 'PLAINTEXT';
    }
    $oauth_config['oauth_signature'] = $this->_makeOauthSig( $url , $method , $oauth_config );

    $oauth_headers = array();
    foreach($oauth_config as $k=>$v){
      $oauth_headers[] = "{$k}=\"{$v}\"";
    }

    return "OAuth realm=\"\", ".implode(", ",$oauth_headers);
   
  }

  private function _makeOauthSig( $url = '' , $method = '' , &$oauth_config = '' )
  {
    $base_string = $this->_makeBaseString( $url , $method , $oauth_config );
    $oauth_str = $this->_urlencode($this->_consumer_secret).'&'.$this->_urlencode($this->_token_secret);
    if ($oauth_config['oauth_signature_method'] == 'PLAINTEXT'){
      return $oauth_str;
    }
    $signature = $this->_urlencode( base64_encode(hash_hmac("sha1", $base_string, $oauth_str, true)) );

    return $signature;
  }

   // according to RFC-3986
  private function _urlencode ( $s )
  {
    return str_replace('%7E', '~', rawurlencode($s));
  }

  private function _makeBaseString( $url = '' , $method = '' , $oauth_config )
  {
    // $url shouldn't include parameters
    if(strpos($url, '?') !== FALSE){
      $base_url = strstr($url, '?', TRUE);
    }
    else {
      $base_url = $url;
    }

    $base_string = $method.'&'.$this->_urlencode($base_url).'&';
    
    // GET parameters need to be ordered properly with the oauth params
    $oauth_queries = array();
    $parsed = parse_url($url);
    if(isset($parsed['query'])){
      foreach(explode('&', $parsed['query']) as $query){
        $oauth_queries[strstr($query, '=', TRUE)] = $query;
      }
    }
    foreach( $oauth_config as $key => $param )
    {
      $oauth_queries[$key] = $key.'='.$param;
    }
    
    // Need keys ordered alphabetically
    ksort($oauth_queries);

    return $base_string . $this->_urlencode( implode('&',$oauth_queries) );
  }
  
  // From http://www.php.net/manual/en/function.http-parse-headers.php#77241
  private function _parseHttpHeaders($header){
    $retVal = array();
    $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $header));
    foreach( $fields as $field ) {
      if( preg_match('/([^:]+): (.+)/m', $field, $match) ) {
        $callback = function($tmp){ 
            return strtoupper($tmp[0]); 
        };
        $match[1] = preg_replace_callback('/(?<=^|[\x09\x20\x2D])./', 
                $callback,
                strtolower(trim($match[1])));
        if( isset($retVal[$match[1]]) ) {
          $retVal[$match[1]] = array($retVal[$match[1]], $match[2]);
        } else {
          $retVal[$match[1]] = trim($match[2]);
        }
      }
    }
    return $retVal;
  }
  
  private function _getApiResponse($curl_resource, $result)
  {
    $response = (object)curl_getinfo( $curl_resource );
    $response->headers = $this->_parseHttpHeaders(mb_substr($result, 0, $response->header_size));
    $body = mb_substr($result, $response->header_size);
    $response->raw_result = $body;
    
    $response->result = is_string($result) ? json_decode(trim($body)) : '';
    // If no result decoded and the body length is > 0, the reponse was not in JSON. Return the raw body.
    if(is_null($response->result) && $response->size_download > 0){
      $response->result = $body;
    }
    return $response;
  }

}











/*****************************
 * Interface class for oauth *
 * token storage             *
 *****************************/
interface SchoologyApi_OauthStorage
{
  /**
   * Given a user ID, return an array containing the 
   * following parameters, or FALSE if none found
   *   'uid' - the ID of the current user (passed as parameter)
   *   'token_key' - the OAuth access key
   *   'token_secret' - the OAuth access secret
   */
  public function getAccessTokens($uid);

  /**
   * Store the request tokens for a given user ID
   */
  public function saveRequestTokens($uid, $token_key, $token_secret);
  
  /**
  * Retrieve request tokens for a given user ID
  */
  public function getRequestTokens($uid);

  /**
   * Replace existing request_tokens for access_tokens
   */
  public function requestToAccessTokens($uid, $token_key, $token_secret);
  
  /**
   * Revoke any existing tokens (e.g. if they're no longer valid)
   */
  public function revokeAccessTokens($uid);
}

