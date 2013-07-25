<?php
require_once 'SchoologyApi.class.php';

class SchoologyContentApi extends SchoologyApi {
  private $schoology_domain = '';
  
  public function __construct( $consumer_key, $consumer_secret, $domain = '', $token_key = '', $token_secret = '') {
    $this->schoology_domain = $domain;
    parent::__construct($consumer_key, $consumer_secret, $domain, $token_key, $token_secret);
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
   * Build url to Schooology import form
   * 
   * @param int      $import_id   schoology import id
   * @param string   $return_url  url to schoology import form
   * @return string
   *    Import Url, used to redirect the user to the Schoology Import Form
   */
  public function buildImportUrl($import_id, $return_url = '', $scheme = 'http') {
    if(!$return_url) {
      $return_url = (@$_SERVER['HTTPS'] && @$_SERVER['HTTPS'] != 'off' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
    return $scheme . '://' . $this->schoology_domain . '/content_app/import/'. $import_id .'?return_url=' . $return_url;
  }
}