# Unofficial Fitbit Client Library for PHP using OAuth2

Wholesale borrows large portions of [djchen/OAuth2-Fitbit](https://github.com/djchen/oauth2-fitbit) (minor change to
 error checking and scope handling) and [pavelrisenberg/fitbitphp](https://github.com/pavelrisenberg/fitbitphp).

Sets a fitbit-php-oauth2-state cookie during auth flow to prevent CSRF attacks. A session must be started beforehand.

Not guaranteed to work under any circumstances, but it's nice when it does.

## Installation

To install, use composer:

```composer require brulath/fitbit-php-oauth2```

## Usage

### Initialization

All below examples will assume a $fitbit is available. It currently is stateful, so you must set the correct token before
using it to make a request.

```php
$fitbit = new brulath\fitbit\FitbitPHPOAuth2([
    'client_id' => 'your_client_id',
    'client_secret' => 'your_client_secret',
    'redirect_uri' => 'https://www.example.com/fitbit/auth',  // must match URI specified in your app on the Fitbit Developer website
    'logger' => $log,
    'auto_request' => true,  // automatically redirect the user to the Fitbit OAuth process if a token doesn't exist
    'auto_refresh' => true,  // automatically refresh expired tokens
]);
$user_oauth2_token = getOAuth2TokenForUserFromMyDatabase();
$fitbit->setToken($user_oauth2_token);
$profile = $fitbit->getProfile();  // read warning below about token refreshes
print_r($profile);
```

### Token Refreshing Warning

I'm lazy, so I've made this library automatically refresh oauth details whenever they've expired mid-call. That means
 after any call the oauth token may have changed, which you will need to check for (and save the new token). I figure
 it's probably easier to check for changed tokens than catching token expiration exceptions and handling those.
 Soz brah.
 
You have two options: checking ```$fitbit->getToken()``` after __every__ call, or subscribing to [events](http://sabre.io/event/).

```php
$fitbit->on('obtain-token', <your_token_saving_function>);
$fitbit->on('refresh-token', <your_token_saving_function>);
```
### Logging

If you want to follow automated events for debugging, grab MonoLog (or other) and pass an instance as 'logger' during initialization.

```bash
composer require monolog/monolog
```
```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$log = new Logger('name');
$log->pushHandler(new StreamHandler('path/to/your.log', Logger::WARNING));

$fitbit = new brulath\fitbit\FitbitPHPOAuth2([
    'logger' => $log,
    // etc.
]);
```

### Authorization

Authorization obtains OAuth2 keys for the Fitbit account in question. You must have a valid client id, client secret,
and redirect uri from the Fitbit developer website to use this library. You must specify all of the scopes you wish
to use here; you will need to re-authorize the user if you want to expand your scopes later.

#### Automated Authorization Flow

If you're lazy (hi!) you can have the library redirect the user to the Fitbit website for you.

```php
$fitbit = new brulath\fitbit\FitbitPHPOAuth2([
    'client_id' => 'your_client_id',
    'client_secret' => 'your_client_secret',
    'redirect_uri' => 'your_post_authorization_redirect_uri',  // must match URI specified in your app on the Fitbit Developer website
    'scope' => ['activity', 'heartrate', 'location', 'nutrition', 'profile', 'settings', 'sleep', 'social', 'weight'], // desired scopes
]);

// A session is required to prevent CSRF
session_start();

$access_token = $fitbit->getToken();  // will redirect user to fitbit ($fitbit->doAuthFlow()). the cookie it sets must survive.

echo "My Fitbit access token is: {$access_token}";
```

#### Manual Authorization Flow

If you're lazy (hi!) you can have the library redirect the user to the Fitbit website for you.

Authorization involves sending the user to Fitbit's website with a 'state' code so we can verify the request came from us.
Store the state and send the user off to the uri.
```php
$auth = $fitbit->getAuthUrlAndState();
saveStateSoWeCanCheckItLater($auth['state']);  // $_SESSION['fitbit-php-oauth2-state'] = $auth['state']
redirectUserToFitbit($auth['uri']);
```

When the user returns to the redirect_uri specified on the Fitbit developer website, there will be a query ($_GET) parameter
set with the state we stored above; check they match to ensure the request originated with us.
```php
$state = retrieveQueryString('state');  // $_GET['state']
$storedState = retrieveStoredState();  // $_SESSION['fitbit-php-oauth2-state']
if ($state != $storedState) {
    throw \Exception("Invalid auth request");
}

$code = retrieveQueryString('code');  // $_GET['code']
$fitbit->handleAuthResponse($code);  // emits obtain-token event
$access_token = $this->getToken();

echo "My Fitbit access token is: {$access_token}";
```

### Restoring access
```php
// If token has expired, the first request you make will additionally make a refresh request
$fitbit->setToken(getAccessTokenJsonFromMyDatabase());
```

### Making a request

Inspect the FitbitPHPOAuth2 class to find the appropriate method. In this case, I want all activities on a date:
```php
$activities = $fitbit->getActivities('2016-02-20');
print_r($activities);
```

## License

The MIT License (MIT).
