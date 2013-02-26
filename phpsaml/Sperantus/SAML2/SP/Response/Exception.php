<?php
/**
 * 
 * SPERANTUS SAML 2.0 TOOLKIT  - LICENSE & DISCLAIMER
 * 
 * Copyright (c) Sperantus 2011 web: www.sperantus.com info@sperantus.com
 * Programmed by: Diego Sainz Gómez
 * 
 * For license details see LICENSE.txt at root directory
 */

/**
 * Class to manage Idp SAML Response errors
 */
class Sperantus_SAML2_SP_Response_Exception extends Exception
{
   const ERR_SIGNATURE_INVALID = 100;   
   const ERR_SIGNATURE_NOTFOUND = 110;
   const ERR_SIGNATURE_INVALID_ALGORITHM = 120;   
   const ERR_SIGNATURE_INVALID_REFERENCE = 130;
   const ERR_DECODE_RESPONSE = 200;
   const ERR_FETCHING_ATTRIBUTE = 300;
   const ERR_AUTH_VALID_UNTIL = 400;
   const ERR_AUTH_EXPIRED = 410;
   const ERR_CONDITIONS_TIMEFRAME_NOT_FOUND = 500;
   
   public static function signatureNotFound()
   {
       return new self('Signature not found in SAML Response', self::ERR_SIGNATURE_NOTFOUND);
   }
   
   public static function invalidReference()
   {
       return new self('Invalid SAMLResponse reference', self::ERR_SIGNATURE_INVALID_REFERENCE);
   }
 
   public static function invalidAlgorithm()
   {
       return new self("Unknown SAML key algorithm", self::ERR_SIGNATURE_INVALID_ALGORITHM);
   }   
   
   public static function invalidSignature()
   {
       return new self("Unknown SAML Response Signature", self::ERR_SIGNATURE_INVALID);       
   }   
   
   public static function authorizationNotValidUntil(DateTime $now, DateTime $validUntil)
   {
       // Transform current time to UTC timezone to match SAML date format
       $now = clone $now;
       $now->setTimezone(new DateTimeZone('UTC'));
       $now = $now->format('r');       
              
       $validUntil = $validUntil->format('r');
       
       return new self("The authorization is not valid until '$validUntil' (current time: '$now')", self::ERR_AUTH_VALID_UNTIL);
   }   

   public static function authorizationExpired(DateTime $now, DateTime $expiresOn)
   {
       // Transform current time to UTC timezone to match SAML date format
       $now = clone $now;
       $now->setTimezone(new DateTimeZone('UTC'));
       $now = $now->format('r');       

       $expiresOn = $expiresOn->format('r');       
       
       return new self("The authorization has expired on '$expiresOn' (current time: '$now')", self::ERR_AUTH_EXPIRED);
   }   

   
   public static function errorParsingSamlResponse($originalResponse, Exception $previousException = null)
   {
       $previousMsg = '';
       if ($previousException) {
           $previousMsg = '(Message: ' . $previousException->getMessage() . ')';
       }
       
            
       return new self("Error parsing SAML 2.0 response $previousMsg: $originalResponse", self::ERR_DECODE_RESPONSE, $previousException);
   }      
   
   public static function errorFetchingAttribute($attributeName, Exception $previousException = null)
   {
       $previousMsg = '';
       if ($previousException) {
           $previousMsg = '(Message: ' . $previousException->getMessage() . ')';
       }
       
       return new self("Error fetching attribute '$attributeName' $previousMsg", self::ERR_FETCHING_ATTRIBUTE, $previousException);
   }      
   
   public static function samlTimeFrameConditionsNotPresent(Exception $previousException = null)
   {
       $previousMsg = '';
       if ($previousException) {
           $previousMsg = '(Message: ' . $previousException->getMessage() . ')';
       }
       
       return new self("Time frame conditions not found in SAML response $previousMsg", self::ERR_CONDITIONS_TIMEFRAME_NOT_FOUND, $previousException);
   }        
}