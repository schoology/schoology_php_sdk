<?php
require_once 'SchoologyApi.class.php';
require_once 'SchoologyExceptions.php';

class SchoologyContentApi extends SchoologyApi {
  private $schoology_site_base = '';
  
  public function __construct( $consumer_key, $consumer_secret, $site_base = '', $token_key = '', $token_secret = '') {
    $this->schoology_site_base = $site_base;
    parent::__construct($consumer_key, $consumer_secret, $site_base, $token_key, $token_secret);
  }
  
  /**
   * Wrapper for importing embed content
   */
  public function importEmbed($title, $embed) {
    $info = array(
      'title' => $title,
      'embed' => $embed,
    );
    return $this->import('embed', $info);
  }
  
  /**
   * Wrapper for importing link content
   */
  public function importLink($title, $url) {
    $info = array(
      'title' => $title,
      'url' => $url,
    );
    return $this->import('link', $info);
  }
  
  /**
   * Wrapper for importing file content
   */
  public function importFile($filepath) {
    $info = array(
      'filepath' => $filepath,
    );
    return $this->import('file', $info);
  }
  
  /**
   * Import content to Schoology servers
   * 
   * @param string  $type   content type embed|link|file 
   * @param array   $info   content info (title, url ..etc)
   * @return
   *    import id and redirect url to Schoology content import form
   */
  public function import($type, $info) {
    
    switch($type) {
      case 'embed':
        $api_result = $this->api('content_app/import/embed', 'POST', $info);
        break;

      case 'link':
        $api_result = $this->api('content_app/import/link', 'POST', $info); 
        break;

      case 'file':
        $info = array('file-attachment' => array(
          'id' => $this->apiFileUpload($info['filepath'])
        ));
        $api_result = $this->api('content_app/import/file', 'POST', $info); 
        break;
    }
    
    return $api_result->result->import_id;
  }
  
  /**
   * Bulk import content into Schoology
   * 
   * @param array   $body   content info
   * 
   * eg,
   *  $body = array(
   *     'link' => array(
   *       array('title' => $link_title, 'url' => $link_url),
   *       ...
   *     ),
   *     
   *     'embed' => $embeds = array(
   *       array('title' => $embed_title, 'embed' => $embed_body),
   *       ...
   *     ),
   *     
   *     'file-attachment' => array('id' => array(
   *       $schoology->apiFileUpload($filepath),
   *       ....
   *     )),
   *   );
   * 
   * @return
   *    import id and redirect url to Schoology content import form
   */
  public function importBulk($body) {
    $api_result = $this->api('content_app/import', 'POST', $body);
    return $api_result->result;
  }
  
  /**
   * Build url to Schooology import form
   * 
   * @param int      $import_id   schoology import id
   * @param string   $return_url  url to schoology import form
   * @return string
   *    Import Url, used to redirect the user to the Schoology Import Form
   */
  public function buildImportUrl($import_id, $return_url = '') {
    if(is_array($import_id)) {
      $import_id_qs = '';
      foreach($import_id as $i) {
        $import_id_qs .= 'import_id[]='.$i.'&';
      }
    }
    else {
      $import_id_qs = 'import_id[]='.$import_id.'&';
    }
    if(!$return_url) {
      $return_url = (@$_SERVER['HTTPS'] && @$_SERVER['HTTPS'] != 'off' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
    return $this->schoology_site_base . '/content_app/import?'. $import_id_qs .'return_url=' . $return_url;
  }
}