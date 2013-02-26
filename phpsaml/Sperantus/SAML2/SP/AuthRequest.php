<?php
/**
 * 
 * SPERANTUS SAML 2.0 TOOLKIT  - LICENSE & DISCLAIMER
 * 
 * Copyright (c) Sperantus 2011 web: www.sperantus.com info@sperantus.com
 * Programmed by: Diego Sainz Gómez
 * 
 * Based on the code of OneLogin (11 Jan 2010, 1.2.2)
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

/**
 * Class to construct a SAML 2.0 Authorization Request via HTTP-GET
 */
class Sperantus_SAML2_SP_AuthRequest
{
    private $_targetUrl;
    private $_consumerUrl;
    private $_issuer;
    
    public function __construct($issuer, $targetUrl, $consumerUrl)
    {
        $this->_issuer = $issuer;
        $this->_targetUrl = $targetUrl;
        $this->_consumerUrl = $consumerUrl;
    }
    
    /**
     * Get the URI to make the SAML authorization request
     * 
     * @return string
     */
    public function getRequestUri()
    {
        $requestXml = $this->getAuthnRequestXml();

        return $this->_getSamlRequestUri($requestXml);
    }
    
    public function getAuthnRequestXml()
    {
        //$assertionConsumerServiceUrl = urle
        $id = uniqid('',true);
        $issueInstant = $this->_getCurrentDateTimeString();
        $assertionConsumerServiceUrl = $this->_escapeXml($this->_consumerUrl);
        $issuer = $this->_escapeXml($this->_issuer);
        
      $request = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"  
    ID="$id" Version="2.0" IssueInstant="$issueInstant"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="$assertionConsumerServiceUrl">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">$issuer</saml:Issuer>
    <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="false">
    </samlp:NameIDPolicy>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
        Comparison="exact">
        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML;
      
      return $request;      
    }
    
    private function _getCurrentDateTimeString()
    {
        $today = new DateTime;
        $tz = new DateTimeZone('UTC');
        $today->setTimezone($tz);
        return $today->format('Y-m-d\TH:i:s\Z');
    }
    
    private function _getSamlRequestUri($xmlString)
    {
        $compressedXml = gzdeflate($xmlString);
        $base64Xml = base64_encode($compressedXml);
 
       return $this->_targetUrl . '?SAMLRequest=' . urlencode($base64Xml);       
    }
    
    
    private function _escapeXml($string)
    {
        // TODO: do an XML-specific escape (Not HTML escaping)
        return htmlentities($string);
    }   
}