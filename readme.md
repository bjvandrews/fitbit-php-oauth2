# Unofficial Fitbit Client Library for PHP using OAuth2

Wholesale borrows large portions of [djchen/OAuth2-Fitbit](https://github.com/djchen/oauth2-fitbit) (minor change to
 error checking and scope handling) and [heyitspavel/fitbitphp](https://github.com/djchen/oauth2-fitbit).

Sets a fitbit-php-oauth2-state cookie during auth flow to prevent CSRF attacks. A session must be started beforehand.

Not guaranteed to work under any circumstances, but it's nice when it does.

## Installation

To install, use composer:

Add ```"brulath/fitbit-php-oauth2": "@dev"``` to your composer.json file's ```require``` section, then ```composer update```.

## Usage

### Magic token acquisition

```php
try {
    $fitbit = new brulath\fitbit\FitBitPHPOauth2(
        'your_client_id',
        'your_client_secret',
        'your_post_authorization_redirect_url',
        ['activity', 'heartrate', 'location', 'profile', 'settings', 'sleep', 'social', 'weight'], // desired scopes
        true  // produce some debugging output in error_log
    );
    
    // A session is required to prevent CSRF
    session_start();
    
    $access_token = $fitbit->get_token();  // will redirect user to fitbit. the cookie it sets must survive.
    
    storeAccessTokenAsJsonInMyDatabase($access_token);
} catch (\Exception $e) {
    print($e);
}
```

### Restoring access
```php

try {
    $fitbit = new brulath\fitbit\FitBitPHPOauth2(
        'your_client_id',
        'your_client_secret',
        'your_post_authorization_redirect_url',
        ['activity', 'heartrate', 'location', 'profile', 'settings', 'sleep', 'social', 'weight'], // desired scopes
        true  // produce some debugging output in error_log
    );
    
    // If token has expired, the first request you make will additionally make a refresh request
    $fitbit->set_token(getAccessTokenJsonFromMyDatabase());
} catch (\Exception $e) {
    print($e);
}
```

### Making a request

Inspect the FitBitPHPOauth2 class to find the appropriate method. In this case, I want all activities on a date:
```php

try {
    $fitbit = new brulath\fitbit\FitBitPHPOauth2(
        'your_client_id',
        'your_client_secret',
        'your_post_authorization_redirect_url',
        ['activity', 'heartrate', 'location', 'profile', 'settings', 'sleep', 'social', 'weight'], // desired scopes
        true  // produce some debugging output in error_log
    );
    $fitbit->set_token(getAccessTokenJsonFromMyDatabase());
    
    $activities = $fitbit->getActivities('2016-02-20');
    print_r($activities);
} catch (\Exception $e) {
    print($e);
}
```

## License

The MIT License (MIT).
