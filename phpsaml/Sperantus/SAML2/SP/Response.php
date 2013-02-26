<?php
/**
 * 
 * SPERANTUS SAML 2.0 TOOLKIT  - LICENSE & DISCLAIMER
 * 
 * Copyright (c) Sperantus 2011 web: www.sperantus.com info@sperantus.com
 * Based on the code of OneLogin (11 Jan 2010, 1.2.2)
 *
 * Copyright (c) 2010, OneLogin, Inc.
 * http://support.onelogin.com/entries/268420-saml-toolkit-for-php
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ONELOGIN, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.* 
 */

require_once __DIR__ . '/../../../../phpsaml/xmlseclibs/xmlseclibs.php';
require_once __DIR__ . '/../../../../phpsaml/Sperantus/SAML2/SP/Response/Exception.php';

/**
 * Class to validate & parse SAML 2.0 Response
 */
class Sperantus_SAML2_SP_Response
{
    private $_publicKey;
    private $_responseXmlDom;
    
    /**
     * Constructor
     * 
     * @throws Sperantus_SAML2_SP_Response_Exception in case of parsing/SAML validation error
     * @param string $publicKey
     * @param string $samlResponseString 
     */
    public function __construct($publicKey, $samlResponseString)
    {
        $this->_publicKey = $publicKey;
        $this->_parseSamlResponse($samlResponseString);
        $this->_validateSignature();
        $this->_validateTimeRange();        
    }    

    /**
     * Get the SAML NameID present in the authorization response
     * 
     * @throws Sperantus_SAML2_SP_Response_Exception
     * 
     * @return string
     */
    public function getNameId() 
    {
        $query = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";        
        $entries = $this->querySamlResponse($query);
        
        try {
        $value = $entries->item(0)->nodeValue;
        } 
        catch (Exception $e) {
            throw Sperantus_SAML2_SP_Response_Exception::errorFetchingAttribute($query, $e);
        }          
        
        return $value;
    }       
    
    /**
     * Query the SAML Response DOM object
     * 
     * @throws Sperantus_SAML2_SP_Response_Exception
     * 
     * @param string $query - XPath query
     * @return DOMNodeList 
     */
    public function querySamlResponse($query)
    {
        try {
            $xpath = new DOMXPath($this->_responseXmlDom);
            $xpath->registerNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");
            $xpath->registerNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
          
            return $xpath->query($query); 
        }
        catch (Exception $e) {
            throw Sperantus_SAML2_SP_Response_Exception::errorFetchingAttribute($query, $e);
        }                
    }    
    
    /**
     * Get the SAML Sha1Passwd attribute present in the authorization response
     * 
     * @throws Sperantus_SAML2_SP_Response_Exception
     * 
     * @return string
     */
    public function getAttribute($attributeName) 
    {
         $query = '/samlp:Response/saml:Assertion/saml:AttributeStatement/'
        . 'saml:Attribute[@Name="' . $attributeName . '"]';        
        
        try {
            $entries = $this->querySamlResponse($query);
            $value = $entries->item(0)->nodeValue;
        } 
        catch (Exception $e) {
            throw Sperantus_SAML2_SP_Response_Exception::errorFetchingAttribute($query, $e);
        }              
        
        return $value;
    }   
    
    /**
     * Get the SAML response XML string
     * 
     * @return string
     */
    public function getResponseXml()
    {
        return $this->_responseXmlDom->saveXML();
    }
    
    /**
     * Decode & load SAML Response
     * 
     * @param type $xmlString 
     */
    private function _parseSamlResponse($xmlString)
    {
        try {
            
            $dom = new DOMDocument();
            $decodedXml = base64_decode($xmlString);   
            if (!@$dom->loadXML($decodedXml)) {
                throw Sperantus_SAML2_SP_Response_Exception::errorParsingSamlResponse($xmlString);
            }
            $this->_responseXmlDom = $dom;
            
        } catch (Exception $e) {
            throw Sperantus_SAML2_SP_Response_Exception::errorParsingSamlResponse($xmlString, $e);
        }
    }   
    
    /**
     * Get the valid time frame for the SAML Response
     * 
     * @return array With 'NotBefore' and 'NotOnOrAfter' indexes as DateTime objects
     */
    private function _getTimeConditions() 
    {
        $query = "/samlp:Response/saml:Assertion/saml:Conditions";                
        $entries = $this->querySamlResponse($query);
        
        try {
            /* @var $value DOMNamedNodeMap */        
            $value = $entries->item(0)->attributes;          

            $notBefore = $value->getNamedItem('NotBefore')->nodeValue;
            $notOnOrAfter = $value->getNamedItem('NotOnOrAfter')->nodeValue;
        } catch (Exception $e) {
            throw Sperantus_SAML2_SP_Response_Exception::samlTimeFrameConditionsNotPresent($e);
        }
        
        return array(
            'NotBefore' => new DateTime($notBefore),
            'NotOnOrAfter' => new DateTime($notOnOrAfter)
        );
    }    
    
    /**
     * Validate that the SAML Response is within the time limits
     * @throws Sperantus_SAML2_SP_Response_Exception
     */
    private function _validateTimeRange()
    {
        $timeRange = $this->_getTimeConditions();
        $now = new DateTime;
        
        if ($now < $timeRange['NotBefore'] ) {
            throw Sperantus_SAML2_SP_Response_Exception::authorizationNotValidUntil($now, $timeRange['NotBefore'] );
        }
        
        if ($now >= $timeRange['NotOnOrAfter']) {
            throw Sperantus_SAML2_SP_Response_Exception::authorizationExpired($now, $timeRange['NotOnOrAfter']);
        }        
    }
    
    /**
     * Validate the SAML Response Signature
     */
    private function _validateSignature()
    {
        $dom = $this->_responseXmlDom;
        
    	$xmlSec = new XMLSecurityDSig();

        $signature = $xmlSec->locateSignature($dom);
    	if (!$signature) {
            throw Sperantus_SAML2_SP_Response_Exception::signatureNotFound();
    	}
        
    	$xmlSec->canonicalizeSignedInfo();
    	$xmlSec->idKeys = array('ID');

    	if (!$xmlSec->validateReference()) {
            throw Sperantus_SAML2_SP_Response_Exception::invalidReference();
    	}

    	$secKey = $xmlSec->locateKey();
    	if (!$secKey ) {
            throw Sperantus_SAML2_SP_Response_Exception::invalidAlgorithm();
    	}

    	$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($secKey, $signature);

        $secKey->loadKey($this->_publicKey);
      
    	if (!$xmlSec->verify($secKey)) {
            throw Sperantus_SAML2_SP_Response_Exception::invalidSignature();
        }
            
    }        
    
}
