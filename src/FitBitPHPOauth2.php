<?php

namespace brulath\fitbit;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Process\Exception\RuntimeException;

/**
 * Fitbit PHP Oauth2 v.1.0.0 Basic Fitbit API wrapper for PHP using OAuth
 * Heavily based upon https://github.com/heyitspavel/fitbitphp & https://github.com/djchen/oauth2-fitbit
 *
 * Sets a fitbit-php-oauth2-state cookie during auth flow to prevent CSRF attacks. A session must be started beforehand.
 *
 * Date: 2015/02/26
 * Requires https://github.com/thephpleague/oauth2-client
 * @version 1.0.0 ($Id$)
 * @license http://opensource.org/licenses/MIT MIT
 */
class FitBitPHPOauth2 {
    const API_URL = 'https://api.fitbit.com/1/';

    /**
     * @var FitbitProvider
     */
    protected $provider;

    /**
     * @var string
     */
    protected $client_id;

    /**
     * @var string
     */
    protected $client_secret;

    /**
     * @var string
     */
    protected $redirect_uri;

    /**
     * @var AccessToken
     */
    protected $access_token;

    protected $metric = true;
    protected $user_agent = 'FitBitPHPOauth2 1.0.0';
    protected $scope = ['activity', 'heartrate', 'location', 'profile', 'settings', 'sleep', 'social', 'weight'];

    protected $debug = false;
    protected $automatically_request_token = true;
    protected $automatically_refresh_tokens = true;

    public function __construct($client_id, $client_secret, $redirect_uri, $scope, $debug = false,
                                $auto_request = true,  $auto_refresh = true) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->redirect_uri = $redirect_uri;
        if (!empty($scope)) {
            $this->scope = $scope;
        }
        $this->debug = $debug;
        $this->automatically_request_token = $auto_request;
        $this->automatically_refresh_tokens = $auto_refresh;
        $this->provider = $this->create_provider();
    }

    /**
     * Fitbit-specific method to convert an OAuth 1.0 token to an OAuth 2.0 one
     * This may be disabled by Fitbit at any time.
     *
     * @param $oauth1_token string Existing valid oauth1 token for a user
     * @param $oauth1_secret string Existing valid oauth1 secret for a user
     * @returns Mixed OAuth2 json-serialized token [access_token, refresh_token, expires] for use in this library
     */
    public function get_oauth2_token_for_oauth1_user($oauth1_token, $oauth1_secret) {
        $refresh_token = "{$oauth1_token}:{$oauth1_secret}";
        $token = $this->provider->getAccessToken('refresh_token', ['refresh_token' => $refresh_token]);
        return $token->jsonSerialize();
    }

    /**
     * Get JSON-serialised token
     * @throws FitbitException
     * @return mixed
     */
    public function get_token() {
        if (empty($this->access_token)) {
            if ($this->automatically_request_token) {
                $this->do_auth_flow();
            } else {
                throw new FitbitTokenMissingException();
            }
        }
        return $this->access_token->jsonSerialize();
    }

    /**
     * @param $token string JSON-serialized token
     */
    public function set_token($token) {
        $this->access_token = new AccessToken($token);
    }

    public function refresh_token() {
        if (empty($this->access_token)) {
            throw new FitbitTokenMissingException();
        }
        $refresh_token = $this->access_token->getRefreshToken();
        $this->access_token = $this->provider->getAccessToken('refresh_token', ['refresh_token' => $refresh_token]);
        $this->debug("Received new access_token: " . print_r($this->access_token, true));
    }

    /**
     * @return string Actual access token - does not include refresh or expiry
     * @throws FitbitTokenMissingException
     */
    public function get_access_token() {
        if (empty($this->access_token)) {
            throw new FitbitTokenMissingException();
        }
        return $this->access_token->getToken();
    }

    /**
     * @return string Actual refresh token
     * @throws FitbitTokenMissingException
     */
    public function get_refresh_token() {
        if (empty($this->access_token)) {
            throw new FitbitTokenMissingException();
        }
        return $this->access_token->getRefreshToken();
    }

    /**
     * @return int Expiration time of token (unix epoch)
     * @throws FitbitTokenMissingException
     */
    public function get_token_expiry() {
        if (empty($this->access_token)) {
            throw new FitbitTokenMissingException();
        }
        return $this->access_token->getExpires();
    }

    /**
     * @return FitbitUser
     * @throws FitbitTokenMissingException
     */
    public function get_resource_owner() {
        if (empty($this->access_token)) {
            throw new FitbitTokenMissingException();
        }
        return $this->provider->getResourceOwner($this->access_token);
    }

    /**
     * Perform the OAuth2 flow to acquire a valid FitBit API token for the current user
     * This function requires:
     *      the user to be accessing the current page using a web browser
     *      the user & server have cookies enabled and can set 'fitbit-php-oauth2-state' cookie successfully
     *      access to unmodified $_GET
     *
     * The user will be redirected to FitBit's API Authorization URL, after which they will be sent to the
     * redirect_url specified on FitBit's website (and in this class's instantiation). You must call this function
     * again when they arrive in order to obtain the state and code $_GET parameters.
     *
     * Upon completion of the auth flow you will either receive an exception (states don't match) or will be able to
     * retrieve the token using get_token()
     *
     * @throws RuntimeException
     */
    public function do_auth_flow() {
        if (!isset($_GET['code'])) {
            // Must call getAuthorizationUrl first in order to generate the state (mitigate CSRF attacks)
            $authorizationUrl = $this->provider->getAuthorizationUrl();
            $_SESSION['fitbit-php-oauth2-state'] = $this->provider->getState();
            // Note: do not use provider->authorize() - it will generate a new state that we cannot capture and check
            header('Location: ' . $authorizationUrl);
            exit;
        } elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['fitbit-php-oauth2-state'])) {
            unset($_SESSION['fitbit-php-oauth2-state']);
            throw new \RuntimeException("Invalid state");
        } else {
            unset($_SESSION['fitbit-php-oauth2-state']);
            $this->access_token = $this->provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);
        }
    }

    /**
     * Get user profile
     *
     * @throws FitBitException
     * @return mixed JSON
     */
    public function getProfile() {
        return $this->read("user/-/profile");
    }

    /**
     * Update user profile
     *
     * @throws FitBitException
     * @param string $gender 'FEMALE', 'MALE' or 'NA'
     * @param string $birthday Date of birth
     * @param string $height Height in cm/inches (as set with setMetric)
     * @param string $nickname Nickname
     * @param string $fullName Full name
     * @param string $timezone Timezone in the format 'America/Los_Angeles'
     * @return mixed JSON
     */
    public function updateProfile($gender = null, $birthday = null, $height = null, $nickname = null, $fullName = null, $timezone = null) {
        $parameters = array_filter([
            'gender' => $gender,
            'birthday' => $birthday,
            'height' => $height,
            'nickname' => $nickname,
            'fullName' => $fullName,
            'timezone' => $timezone,
        ]);
        return $this->update('user/-/profile', $parameters);
    }

    /**
     * https://wiki.fitbit.com/display/API/API-Get-Activity-Daily-Goals
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getDailyGoals() {
        return $this->read("user/-/activities/goals/daily");
    }

    /**
     * https://wiki.fitbit.com/display/API/API-Update-Activity-Daily-Goals
     * @param $caloriesOut int
     * @param $activeMinutes int
     * @param $floors int
     * @param $distance float
     * @param $steps int
     * @return mixed FitbitResponse
     */
    public function updateDailyGoals($steps = null, $floors = null, $distance = null, $activeMinutes = null, $caloriesOut = null) {
        $parameters = array_filter([
            'steps' => $steps,
            'floors' => $floors,
            'distance' => $distance,
            'activeMinutes' => $activeMinutes,
            'caloriesOut' => $caloriesOut,
        ]);
        return $this->update("user/-/activities/goals/daily", $parameters);
    }

    /**
     * https://wiki.fitbit.com/display/API/API-Get-Activity-Weekly-Goals
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getWeeklyGoals() {
        return $this->read("user/-/activities/goals/weekly");
    }

    /**
     * https://wiki.fitbit.com/display/API/API-Update-Activity-Weekly-Goals
     * @param $floors int
     * @param $distance float
     * @param $steps int
     * @return mixed FitbitResponse
     */
    public function updateWeeklyGoals($floors = null, $distance = null, $steps = null) {
        $parameters = array_filter([
            'floors' => $floors,
            'distance' => $distance,
            'steps' => $steps,
        ]);
        return $this->update("user/-/activities/goals/daily", $parameters);
    }


    /**
     * Get user activities for specific date
     *
     * @throws FitBitException
     * @param  string $date Y-m-d
     * @return mixed FitbitResponse
     */
    public function getActivities($date) {
        return $this->read("user/-/activities/date/" . $date);
    }


    /**
     * Get user recent activities
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getRecentActivities() {
        return $this->read("user/-/activities/recent");
    }


    /**
     * Get user frequent activities
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFrequentActivities() {
        return $this->read("user/-/activities/frequent");
    }


    /**
     * Get user favorite activities
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFavoriteActivities() {
        return $this->read("user/-/activities/favorite");
    }


    /**
     * Log user activity
     *
     * @throws FitBitException
     * @param string $date Activity date Y-m-d
     * @param string $time Activity time H:i
     * @param string $activityId Activity Id (or Intensity Level Id) from activities database,
     *                                  see http://wiki.fitbit.com/display/API/API-Log-Activity
     * @param string $duration Duration millis
     * @param string $calories Manual calories to override Fitbit estimate
     * @param string $distance Distance in km/miles (as set with setMetric)
     * @param string $distanceUnit Distance unit string (see http://wiki.fitbit.com/display/API/API-Distance-Unit)
     * @param string $activityName Name
     * @return mixed FitbitResponse
     */
    public function logActivity($date, $time, $activityId, $duration, $calories = null, $distance = null, $distanceUnit = null, $activityName = null) {
        $distanceUnits = array('Centimeter', 'Foot', 'Inch', 'Kilometer', 'Meter', 'Mile', 'Millimeter', 'Steps', 'Yards');

        $parameters = array();
        $parameters['date'] = $date;
        $parameters['startTime'] = $time;
        if (isset($activityName)) {
            $parameters['activityName'] = $activityName;
            $parameters['manualCalories'] = $calories;
        } else {
            $parameters['activityId'] = $activityId;
            if (isset($calories)) {
                $parameters['manualCalories'] = $calories;
            }
        }
        $parameters['durationMillis'] = $duration;
        if (isset($distance)) {
            $parameters['distance'] = $distance;
        }
        if (isset($distanceUnit) && in_array($distanceUnit, $distanceUnits)) {
            $parameters['distanceUnit'] = $distanceUnit;
        }
        return $this->create("user/-/activities", $parameters);
    }


    /**
     * Delete user activity
     *
     * @throws FitBitException
     * @param string $id Activity log id
     * @return bool
     */
    public function deleteActivity($id) {
        return $this->delete("user/-/activities/" . $id);
    }


    /**
     * Add user favorite activity
     *
     * @throws FitBitException
     * @param string $id Activity log id
     * @return bool
     */
    public function addFavoriteActivity($id) {
        return $this->create("user/-/activities/favorite/" . $id);
    }


    /**
     * Delete user favorite activity
     *
     * @throws FitBitException
     * @param string $id Activity log id
     * @return bool
     */
    public function deleteFavoriteActivity($id) {
        return $this->delete("user/-/activities/favorite/" . $id);
    }


    /**
     * Get full description of specific activity
     *
     * @throws FitBitException
     * @param  string $id Activity log Id
     * @return mixed FitbitResponse
     */
    public function getActivity($id) {
        return $this->read("activities/" . $id);
    }


    /**
     * Get a tree of all valid Fitbit public activities as well as private custom activities the user createds
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function browseActivities() {
        return $this->read("activities");
    }


    /**
     * Get user foods for specific date
     *
     * @throws FitBitException
     * @param  string $date Y-m-d
     * @return mixed FitbitResponse
     */
    public function getFoods($date) {
        return $this->read("user/-/foods/log/date/" . $date);
    }


    /**
     * Get user recent foods
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getRecentFoods() {
        return $this->read("user/-/foods/log/recent");
    }


    /**
     * Get user frequent foods
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFrequentFoods() {
        return $this->read("user/-/foods/log/frequent");
    }


    /**
     * Get user favorite foods
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFavoriteFoods() {
        return $this->read("user/-/foods/log/favorite");
    }


    /**
     * Log user food
     *
     * @throws FitBitException
     * @param string $date Y-m-d Food log date
     * @param string $foodId Food Id from foods database (see searchFoods)
     * @param string $mealTypeId Meal Type Id from foods database (see searchFoods)
     * @param string $unitId Unit Id, should be allowed for this food (see getFoodUnits and searchFoods)
     * @param string $amount Amount in specified units
     * @param string $foodName Unknown
     * @param string $calories Unknown
     * @param string $brandName Unknown
     * @param string $nutrition Unknown
     * @return mixed FitbitResponse
     */
    public function logFood($date, $foodId, $mealTypeId, $unitId, $amount, $foodName = null, $calories = null, $brandName = null, $nutrition = null) {
        $parameters = array();
        $parameters['date'] = $date;
        if (isset($foodName)) {
            $parameters['foodName'] = $foodName;
            $parameters['calories'] = $calories;
            if (isset($brandName)) {
                $parameters['brandName'] = $brandName;
            }
            if (isset($nutrition)) {
                foreach ($nutrition as $i => $value) {
                    $parameters[$i] = $nutrition[$i];
                }
            }
        } else {
            $parameters['foodId'] = $foodId;
        }
        $parameters['mealTypeId'] = $mealTypeId;
        $parameters['unitId'] = $unitId;
        $parameters['amount'] = $amount;

        return $this->create("user/-/foods/log", $parameters);
    }


    /**
     * Delete user food
     *
     * @throws FitBitException
     * @param string $id Food log id
     * @return bool
     */
    public function deleteFood($id) {
        return $this->delete("user/-/foods/log/" . $id);
    }


    /**
     * Add user favorite food
     *
     * @throws FitBitException
     * @param string $id Food log id
     * @return bool
     */
    public function addFavoriteFood($id) {
        return $this->create("user/-/foods/log/favorite/" . $id);
    }


    /**
     * Delete user favorite food
     *
     * @throws FitBitException
     * @param string $id Food log id
     * @return bool
     */
    public function deleteFavoriteFood($id) {
        return $this->delete("user/-/foods/log/favorite/" . $id);
    }


    /**
     * Get user meal sets
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getMeals() {
        return $this->read("user/-/meals");
    }


    /**
     * Get food units library
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFoodUnits() {
        return $this->read("foods/units");
    }


    /**
     * Search for foods in foods database
     *
     * @throws FitBitException
     * @param string $query Search query
     * @return mixed FitbitResponse
     */
    public function searchFoods($query) {
        return $this->read("foods/search", $query);
    }


    /**
     * Get description of specific food from food db (or private for the user)
     *
     * @throws FitBitException
     * @param  string $id Food Id
     * @return mixed FitbitResponse
     */
    public function getFood($id) {
        return $this->read("foods/" . $id);
    }


    /**
     * Create private foods for a user
     *
     * @throws FitBitException
     * @param string $name Food name
     * @param string $defaultFoodMeasurementUnitId Unit id of the default measurement unit
     * @param string $defaultServingSize Default serving size in measurement units
     * @param string $calories Calories in default serving
     * @param string $description
     * @param string $formType ("LIQUID" or "DRY)
     * @param string $nutrition Array of nutritional values, see http://wiki.fitbit.com/display/API/API-Create-Food
     * @return mixed FitbitResponse
     */
    public function createFood($name, $defaultFoodMeasurementUnitId, $defaultServingSize, $calories, $description = null, $formType = null, $nutrition = null) {
        $parameters = array();
        $parameters['name'] = $name;
        $parameters['defaultFoodMeasurementUnitId'] = $defaultFoodMeasurementUnitId;
        $parameters['defaultServingSize'] = $defaultServingSize;
        $parameters['calories'] = $calories;
        if (isset($description)) {
            $parameters['description'] = $description;
        }
        if (isset($formType)) {
            $parameters['formType'] = $formType;
        }
        if (isset($nutrition)) {
            foreach ($nutrition as $i => $value) {
                $parameters[$i] = $nutrition[$i];
            }
        }

        return $this->create("foods", $parameters);
    }


    /**
     * Get user water log entries for specific date
     *
     * @throws FitBitException
     * @param  string $date Y-m-d
     * @return mixed FitbitResponse
     */
    public function getWater($date) {
        return $this->read("user/-/foods/log/water/date/" . $date);
    }


    /**
     * Log user water
     *
     * @throws FitBitException
     * @param string $date Y-m-d Log entry date (set proper timezone, which could be fetched via getProfile)
     * @param string $amount Amount in ml/fl oz (as set with setMetric) or waterUnit
     * @param string $waterUnit Water Unit ("ml", "fl oz" or "cup")
     * @return mixed FitbitResponse
     */
    public function logWater($date, $amount, $waterUnit = null) {
        $waterUnits = array('ml', 'fl oz', 'cup');

        $parameters = array();
        $parameters['date'] = $date;
        $parameters['amount'] = $amount;
        if (isset($waterUnit) && in_array($waterUnit, $waterUnits)) {
            $parameters['unit'] = $waterUnit;
        }

        return $this->create("user/-/foods/log/water", $parameters);
    }


    /**
     * Delete user water record
     *
     * @throws FitBitException
     * @param string $id Water log id
     * @return bool
     */
    public function deleteWater($id) {
        return $this->delete("user/-/foods/log/water/" . $id);
    }


    /**
     * Get user sleep log entries for specific date
     *
     * @throws FitBitException
     * @param  string $date Y-m-d
     * @return mixed FitbitResponse
     */
    public function getSleep($date) {
        return $this->read("user/-/sleep/date/" . $date);
    }


    /**
     * Log user sleep
     *
     * @throws FitBitException
     * @param string $date Sleep date Y-m-d
     * @param string $start_time Sleep start time H:i
     * @param string $duration Duration millis
     * @return mixed FitbitResponse
     */
    public function logSleep($date, $start_time, $duration) {
        $parameters = array();
        $parameters['date'] = $date;
        $parameters['startTime'] = $start_time;
        $parameters['duration'] = $duration;

        return $this->create("user/-/sleep", $parameters);
    }


    /**
     * Delete user sleep record
     *
     * @throws FitBitException
     * @param string $id Activity log id
     * @return bool
     */
    public function deleteSleep($id) {
        return $this->delete("user/-/sleep/" . $id);
    }


    /**
     * Get user fat goal
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFatGoal() {
        return $this->read("user/-/body/log/fat/goal");
    }

    /**
     * Get user body measurements
     *
     * @throws FitBitException
     * @param  string $date Y-m-d
     * @return mixed FitbitResponse
     */
    public function getBody($date) {
        return $this->read("user/-/body/date/" . $date);
    }

    /**
     * Log user body measurements
     *
     * @throws FitBitException
     * @param string $date Y-m-d Date Log entry date (set proper timezone, which could be fetched via getProfile)
     * @param string $weight Float number. For en_GB units, provide floating number of stones (i.e. 11 st. 4 lbs = 11.2857143)
     * @param string $fat Float number
     * @return mixed FitbitResponse
     */

    public function logBody($date, $weight = null, $fat = null) {
        $parameters = array_filter([
            'date' => $date,
            '$weight' => $weight,
            '$fat' => $fat,
        ]);
        return $this->create("user/-/body", $parameters);
    }


    /**
     * Log user weight
     *
     * @throws FitBitException
     * @param string $weight Float number. For en_GB units, provide floating number of stones (i.e. 11 st. 4 lbs = 11.2857143)
     * @param string $date Y-m-d If present, log entry date, now by default (set proper timezone, which could be fetched via getProfile)
     * @return bool
     */
    public function logWeight($weight, $date = null) {
        $parameters = array_filter([
            'date' => $date,
            'weight' => $weight,
        ]);
        return $this->create("user/-/body/weight.", $parameters);
    }

    /**
     * Launch TimeSeries requests
     *
     * Allowed types are:
     *            'caloriesIn', 'water'
     *
     *            'caloriesOut', 'steps', 'distance', 'floors', 'elevation', 'heart',
     *            'minutesSedentary', 'minutesLightlyActive', 'minutesFairlyActive', 'minutesVeryActive',
     *            'activityCalories',
     *
     *            'tracker_caloriesOut', 'tracker_steps', 'tracker_distance', 'tracker_floors', 'tracker_elevation'
     *
     *            'startTime', 'timeInBed', 'minutesAsleep', 'minutesAwake', 'awakeningsCount',
     *            'minutesToFallAsleep', 'minutesAfterWakeup',
     *            'efficiency'
     *
     *            'weight', 'bmi', 'fat'
     *
     * @throws FitBitException
     * @param string $type
     * @param  $base_date string Y-m-d or 'today', to_period
     * @param  $to_period string Y-m-d or '1d, 7d, 30d, 1w, 1m, 3m, 6m, 1y, max'
     * @return array
     */
    public function getTimeSeries($type, $base_date, $to_period) {

        switch ($type) {
            case 'caloriesIn':
                $path = 'foods/caloriesIn';
                break;
            case 'water':
                $path = 'foods/water';
                break;

            case 'caloriesOut':
                $path = 'activities/calories';
                break;
            case 'steps':
                $path = 'activities/steps';
                break;
            case 'distance':
                $path = 'activities/distance';
                break;
            case 'floors':
                $path = 'activities/floors';
                break;
            case 'elevation':
                $path = 'activities/elevation';
                break;
            case 'heart':
                $path = 'activities/heart';
                break;
            case 'minutesSedentary':
                $path = 'activities/minutesSedentary';
                break;
            case 'minutesLightlyActive':
                $path = 'activities/minutesLightlyActive';
                break;
            case 'minutesFairlyActive':
                $path = 'activities/minutesFairlyActive';
                break;
            case 'minutesVeryActive':
                $path = 'activities/minutesVeryActive';
                break;
            case 'activeScore':
                $path = 'activities/activeScore';
                break;
            case 'activityCalories':
                $path = 'activities/activityCalories';
                break;

            case 'tracker_caloriesOut':
                $path = 'activities/tracker/calories';
                break;
            case 'tracker_steps':
                $path = 'activities/tracker/steps';
                break;
            case 'tracker_distance':
                $path = 'activities/tracker/distance';
                break;
            case 'tracker_floors':
                $path = 'activities/tracker/floors';
                break;
            case 'tracker_elevation':
                $path = 'activities/tracker/elevation';
                break;
            case 'tracker_activeScore':
                $path = 'activities/tracker/activeScore';
                break;

            case 'startTime':
                $path = 'sleep/startTime';
                break;
            case 'timeInBed':
                $path = 'sleep/timeInBed';
                break;
            case 'minutesAsleep':
                $path = 'sleep/minutesAsleep';
                break;
            case 'awakeningsCount':
                $path = 'sleep/awakeningsCount';
                break;
            case 'minutesAwake':
                $path = 'sleep/minutesAwake';
                break;
            case 'minutesToFallAsleep':
                $path = 'sleep/minutesToFallAsleep';
                break;
            case 'minutesAfterWakeup':
                $path = 'sleep/minutesAfterWakeup';
                break;
            case 'efficiency':
                $path = 'sleep/efficiency';
                break;


            case 'weight':
                $path = 'body/weight';
                break;
            case 'bmi':
                $path = 'body/bmi';
                break;
            case 'fat':
                $path = 'body/fat';
                break;

            default:
                return false;
        }

        return $this->read("user/-/" . $path . "/date/{$base_date}/{$to_period}");
    }


    /**
     * Launch IntradayTimeSeries requests
     *
     * Allowed types are:
     *            'calories', 'steps', 'floors', 'elevation', 'distance', 'heart'
     *
     * @throws FitBitException
     * @param string $type
     * @param  $date string Y-m-d or 'today'
     * @param  $start_time string Y-m-d
     * @param  $end_time string Y-m-d
     * @return object
     */
    public function getIntradayTimeSeries($type, $date, $start_time = null, $end_time = null) {
        switch ($type) {
            case 'calories':
                $path = 'activities/calories';
                break;
            case 'steps':
                $path = 'activities/steps';
                break;
            case 'floors':
                $path = 'activities/floors';
                break;
            case 'elevation':
                $path = 'activities/elevation';
                break;
            case 'distance':
                $path = 'activities/distance';
                break;
            case 'heart':
                $path = 'activities/heart';
                break;

            default:
                print("Not a valid intradaytimeseries type.");
                return false;
        }

        $times = (!empty($start_time) && !empty($end_time)) ? "/time/{$start_time}/{$end_time}" : '';
        return $this->read("user/-/" . $path . "/date/{$date}/1d{$times}");
    }


    /**
     * Get user's activity statistics (lifetime statistics from the tracker device and total numbers including the manual activity log entries)
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getActivityStats() {
        return $this->read("user/-/activities");
    }


    /**
     * Get list of devices and their properties
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getDevices() {
        return $this->read("user/-/devices");
    }

    /**
     * Get user friends
     *
     * @throws FitBitException
     * @return mixed FitbitResponse
     */
    public function getFriends() {
        return $this->read("user/-/friends");
    }

    /**
     * Get user's friends leaderboard
     *
     * @throws FitBitException
     * @param string $period Depth ('7d' or '30d')
     * @return mixed FitbitResponse
     */
    public function getFriendsLeaderboard($period = '7d') {
        return $this->read("user/-/friends/leaders/" . $period);
    }

    /**
     * Invite user to become friends
     *
     * @throws FitBitException
     * @param string $invitedUserId Invite user by id
     * @param string $invitedUserEmail Invite user by email address (could be already Fitbit member or not)
     * @return bool
     */
    public function inviteFriend($invitedUserId = null, $invitedUserEmail = null) {
        $parameters = array_filter([
            'invitedUserId' => $invitedUserId,
            'invitedUserEmail' => $invitedUserEmail,
        ]);
        return $this->create("user/-/friends/invitations", $parameters);
    }


    /**
     * Accept invite to become friends from user
     *
     * @throws FitBitException
     * @param string $userId Id of the inviting user
     * @return bool
     */
    public function acceptFriend($userId) {
        $parameters = array();
        $parameters['accept'] = 'true';
        return $this->create("user/-/friends/invitations/" . $userId, $parameters);
    }


    /**
     * Accept invite to become friends from user
     *
     * @throws FitBitException
     * @param string $userId Id of the inviting user
     * @return bool
     */
    public function rejectFriend($userId) {
        $parameters = array();
        $parameters['accept'] = 'false';
        return $this->create("user/-/friends/invitations/" . $userId, $parameters);
    }


    /**
     * Add subscription
     *
     * @throws FitBitException
     * @param string $id Subscription Id
     * @param string $path Subscription resource path (beginning with slash). Omit to subscribe to all user updates.
     * @param string $subscriberId ID to be returned by fitbit in their callbacks
     * @param bool $delete_existing_subscriptions Remove any existing subscriptions for this access_token
     * @return mixed
     */
    public function addSubscription($id, $path = null, $subscriberId = null, $delete_existing_subscriptions = false) {
        if ($delete_existing_subscriptions) {
            $this->delete_existing_subscriptions();
        }
        $userHeaders = array();
        if ($subscriberId) {
            $userHeaders['X-Fitbit-Subscriber-Id'] = $subscriberId;
        }
        $path = !empty($path) ? "/{$path}" : '';

        return $this->post("user/-" . $path . "/apiSubscriptions/" . $id, null, null, $userHeaders);
    }

    /**
     * Helper method; if you only have one subscriber end point, it's probably easiest to make sure any existing
     * subscriptions are deleted before resubscribing; you'll get 409 conflict exceptions if the user is already
     * subscribed to your client_id.
     */
    private function delete_existing_subscriptions() {
        $subscriptions = $this->getSubscriptions();
        if (!empty($subscriptions) && !empty($subscriptions['apiSubscriptions'])) {
            foreach ($subscriptions['apiSubscriptions'] as &$subscription) {
                $this->deleteSubscription($subscription['subscriptionId']);
                $this->debug("Deleted subscription {$subscription['subscriptionId']}");
            }
        }
    }


    /**
     * Delete user subscription
     *
     * @throws FitBitException
     * @param string $id Subscription Id
     * @param string $path Subscription resource path (beginning with slash)
     * @return bool
     */
    public function deleteSubscription($id, $path = null) {
        $path = !empty($path) ? "/{$path}" : '';
        return $this->delete("user/-" . $path . "/apiSubscriptions/" . $id);
    }


    /**
     * Get list of user's subscriptions for this application
     *
     * @throws FitBitException
     * @return mixed
     */
    public function getSubscriptions() {
        return $this->read("user/-/apiSubscriptions");
    }


    /**
     * Get CLIENT+VIEWER and CLIENT rate limiting quota status
     *
     * @throws FitBitException
     * @return FitBitRateLimiting
     */
    public function getRateLimit() {
        $xmlClientAndUser = $this->read("account/clientAndViewerRateLimitStatus");
        $xmlClient = $this->read("account/clientRateLimitStatus");
        return new FitBitRateLimiting(
            $xmlClientAndUser['rateLimitStatus']['remainingHits'],
            $xmlClient['rateLimitStatus']['remainingHits'],
            $xmlClientAndUser['rateLimitStatus']['resetTime'],
            $xmlClient['rateLimitStatus']['resetTime'],
            $xmlClientAndUser['rateLimitStatus']['hourlyLimit'],
            $xmlClient['rateLimitStatus']['hourlyLimit']
        );
    }


    /**
     * Helpers
     */

    /**
     * Use League OAuth2
     * @return FitbitProvider
     */
    private function create_provider() {
        $provider = new FitbitProvider([
            'clientId' => $this->client_id,
            'clientSecret' => $this->client_secret,
            'redirectUri' => $this->redirect_uri,
        ]);
        $provider->setScope($this->scope);
        return $provider;
    }

    private function process_request($request) {
        return $this->provider->getResponse($request);
    }

    public function has_token_expired() {
        if (empty($this->access_token)) {
            throw new \RuntimeException("No token available to check.");
        }
        return $this->access_token->hasExpired();
    }

    private function get_or_refresh_token_if_missing_or_expired() {
        if (empty($this->access_token)) {
            if ($this->automatically_request_token) {
                $this->do_auth_flow();
            } else {
                throw new FitbitTokenMissingException();
            }
        }
        if ($this->has_token_expired()) {
            if ($this->automatically_refresh_tokens) {
                $this->refresh_token();
            } else {
                throw new FitbitTokenExpiredException();
            }
        }
    }

    private function get($path, $query = null) {
        $this->get_or_refresh_token_if_missing_or_expired();

        $path = static::API_URL . $path . '.json' . (!empty($query) ? http_build_query($query) : "");
        $this->debug("GET: {$path}");
        $request = $this->provider->getAuthenticatedRequest('GET', $path, $this->access_token);
        return $this->process_request($request);
    }

    private function post($path, $parameters = null, $query = null, $headers = []) {
        $this->get_or_refresh_token_if_missing_or_expired();

        $query_string = !empty($query) ? http_build_query($query) : "";
        $form_string = !empty($parameters) ? http_build_query($parameters) : "";
        $headers['content-type'] = 'application/x-www-form-urlencoded';
        $params = ['headers' => $headers, 'body' => $form_string];

        $path = static::API_URL . $path . '.json' . $query_string;
        $this->debug("POST: {$path}");
        $request = $this->provider->getAuthenticatedRequest('POST', $path, $this->access_token, $params);
        return $this->process_request($request);
    }

    private function create($path, $parameters = null, $query = null) {
        return $this->post($path, $parameters, $query);
    }

    private function read($path, $query = null) {
        return $this->get($path, $query);
    }

    private function update($path, $parameters = null, $query = null) {
        return $this->post($path, $parameters, $query);
    }

    private function delete($path, $parameters = null, $query = null) {
        $this->get_or_refresh_token_if_missing_or_expired();

        $query_string = !empty($query) ? http_build_query($query) : "";
        $form_string = !empty($parameters) ? http_build_query($parameters) : "";
        $headers['content-type'] = 'application/x-www-form-urlencoded';
        $params = ['headers' => $headers, 'body' => $form_string];

        $path = static::API_URL . $path . '.json' . $query_string;
        $this->debug("DELETE: {$path}");
        $request = $this->provider->getAuthenticatedRequest('DELETE', $path, $this->access_token, $params);
        return $this->process_request($request);
    }

    private function debug($msg) {
        if ($this->debug) {
            error_log(json_encode($msg));
        }
    }
}

class FitbitException extends \Exception {
    protected $message = "Unknown Fitbit Exception";
}

class FitbitTokenMissingException extends FitbitException {
    protected $message = "Fitbit oauth token missing";
}

class FitbitTokenExpiredException extends FitbitException {
    protected $message = "Fitbit oauth token expired";
}

class FitBitResponse {
    public $response;
    public $code;

    public function __construct($response, $success) {
        $this->response = $response;
        $this->success = $success;
    }

}

class FitBitRateLimiting {
    public $viewer;
    public $viewerReset;
    public $viewerQuota;
    public $client;
    public $clientReset;
    public $clientQuota;

    public function __construct($viewer, $client, $viewerReset = null, $clientReset = null, $viewerQuota = null, $clientQuota = null) {
        $this->viewer = $viewer;
        $this->viewerReset = $viewerReset;
        $this->viewerQuota = $viewerQuota;
        $this->client = $client;
        $this->clientReset = $clientReset;
        $this->clientQuota = $clientQuota;
    }

}

/**
 * Copied here to fix error in checkResponse, otherwise identical to https://github.com/djchen/oauth2-fitbit
 */
class FitbitProvider extends AbstractProvider {
    use BearerAuthorizationTrait;
    const DEBUG = false;

    /**
     * Fitbit URL.
     *
     * @const string
     */
    const BASE_FITBIT_URL = 'https://www.fitbit.com';

    /**
     * Fitbit API URL.
     *
     * @const string
     */
    const BASE_FITBIT_API_URL = 'https://api.fitbit.com';

    protected $scope = ['activity', 'heartrate', 'location', 'nutrition', 'profile', 'settings', 'sleep', 'social', 'weight'];

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl() {
        return static::BASE_FITBIT_URL . '/oauth2/authorize';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params) {
        return static::BASE_FITBIT_API_URL . '/oauth2/token';
    }

    /**
     * Returns the url to retrieve the resource owners's profile/details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token) {
        return static::BASE_FITBIT_API_URL . '/1/user/-/profile.json';
    }

    public function setScope($scope) {
        $this->scope = $scope;
    }

    /**
     * Returns all scopes available from Fitbit.
     * It is recommended you only request the scopes you need!
     *
     * @return array
     */
    protected function getDefaultScopes() {
        return $this->scope;
    }

    /**
     * Checks Fitbit API response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data) {
        if (static::DEBUG) {
            error_log(json_encode($response));
            error_log(json_encode($data));
            error_log($response->getReasonPhrase());
        }
        if ($response->getStatusCode() >= 400) {
            $message = "Failed: " . $response->getStatusCode() . " " . json_encode($response);
            throw new IdentityProviderException($message, $response->getStatusCode(), $data);
        }
    }

    /**
     * Returns the string used to separate scopes.
     *
     * @return string
     */
    protected function getScopeSeparator() {
        return ' ';
    }

    /**
     * Returns authorization parameters based on provided options.
     * Fitbit does not use the 'approval_prompt' param and here we remove it.
     *
     * @param array $options
     * @return array Authorization parameters
     */
    protected function getAuthorizationParameters(array $options) {
        $params = parent::getAuthorizationParameters($options);
        unset($params['approval_prompt']);
        if (!empty($options['prompt'])) {
            $params['prompt'] = $options['prompt'];
        }
        return $params;
    }

    /**
     * Builds request options used for requesting an access token.
     *
     * @param  array $params
     * @return array
     */
    protected function getAccessTokenOptions(array $params) {
        $options = parent::getAccessTokenOptions($params);
        $options['headers']['Authorization'] =
            'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret);
        return $options;
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return FitbitUser
     */
    public function createResourceOwner(array $response, AccessToken $token) {
        return new FitbitUser($response);
    }
}

class FitbitUser implements ResourceOwnerInterface {
    /**
     * @var string
     */
    protected $encodedId;

    /**
     * @var string
     */
    protected $displayName;

    /**
     * @param  array $response
     */
    public function __construct(array $response) {
        $userInfo = $response['user'];
        $this->encodedId = $userInfo['encodedId'];
        $this->displayName = $userInfo['displayName'];
    }

    public function getId() {
        return $this->encodedId;
    }

    /**
     * Get the display name.
     *
     * @return string
     */
    public function getDisplayName() {
        return $this->displayName;
    }

    /**
     * Get user data as an array.
     *
     * @return array
     */
    public function toArray() {
        return [
            'encodedId' => $this->encodedId,
            'displayName' => $this->displayName
        ];
    }
}
