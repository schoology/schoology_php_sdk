#Schoology API - PHP SDK

The Schoology SDK encompasses all necessary parts, including the initial SSO SAML login request, requesting an oAuth access token, and making calls to the Schoology API. It is by no means necessary to create an application. If you don't want to use one or are writing an application not in PHP, you can take a look at them as an example for the types of operations that you will need to do.

##Two-legged oauth
Every Schoology user can generate unique two-legged oauth keys:
1. Log into Schoology
2. Navigate to /api. 
3. Click "Request API Keys"
4. Consumer Key and Consumer Secret will be generated

######Making two-legged API call with SDK
1. Create constants for your consumer key and consumer secret
2. When constructing the Class, the token_key & token_secret parameters should be blank and the two_legged parameter should be set to TRUE
```php
require_once('application/schoology_sdk/SchoologyApi.class.php');
$this->schoology = new SchoologyApi(SCHOOLOGY_CONSUMER_KEY, SCHOOLOGY_CONSUMER_SECRET, '', '','', TRUE); 
```

##Three-legged oauth
When using the API on behalf of a Schoology Application, you must use each applications' unique oauth credentials. To find the credentials after adding an app:
1. Navigate to /apps/publisher
2. For each app click on the "options" action link and oauth info to see the application's consumer key and consumer secret.

######Making three-legged API call with SDK
When making three-legged API calls the authorization flow is more complex:
1. Using the application's consumer key and consumer secret a call will be made to /oauth/request_token to get request tokens.
2. Using the request token another call will be made to /oauth/authorize to get an access token.
3. This access token can then be used to make the correct Authorization headers to make normal API calls. This access token should be stored in a database and used for future API calls
The PHP SDK will take care of this entire OAuth handshake for you

For more detailled information about Authorization be see http://developers.schoology.com/api-documentation/authentication

##Using the API
All calls to the API can be done using the api() function in SchoologyApi.class.php file
######api() parameters
1. $url  - The API endpoint you are accessing (Ex: 'users/5' to get user with uid = 5)
2. $method - Defaults to GET 
3. $body - If doing a POST or PUT, a request body needs to be sent in
4. $extra_headers  - Any extra request Headers

######Sample API Response
A response with a 20x response code means the request was successful:

Headers
```
HTTP/1.1 200 OK
Date: Thu, 10 Jul 2014 16:21:25 GMT
Server: Apache/2.2.20 (Ubuntu)
Vary: Host,Accept-Encoding
X-Powered-By: PHP/5.4.19-1~tooptee10+1
Last-Modified: Thu, 10 Jul 2014 16:21:25 +0000
Cache-Control: no-cache, no-store, must-revalidate, post-check=0, pre-check=0
ETag: "1405009285"
X-Schoology: API
Content-Length: 681
Access-Control-Allow-Origin: *
Connection: close
Content-Type: application/json; charset=UTF-8
```
Body
```json
{
    "course": [
        {
            "id": 1407691,
            "title": "Time Travel",
            "course_code": "CC106",
            "department": "",
            "description": "",
            "credits": 0,
            "subject_area": 0,
            "grade_level_range_start": 12,
            "grade_level_range_end": 14,
            "synced": 1,
            "building_id": "344232"
        },
        {
            "id": 5410559,
            "title": "FS1 Course",
            "course_code": "",
            "department": "",
            "description": "",
            "credits": 0,
            "subject_area": 2,
            "grade_level_range_start": 6,
            "grade_level_range_end": 0,
            "synced": 0,
            "building_id": "5171921"
        }
    ],
    "total": "2",
    "links": {
        "self": "http:\/\/...\/v1\/courses?start=0&limit=20"
    }
}
```

A response with a 40x response code means the request was unsuccessful :

For any additional information please visit http://developers.schoology.com/
