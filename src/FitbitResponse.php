<?php

namespace brulath\fitbit;

class FitbitResponse {
    public $response;
    public $code;

    public function __construct($response, $success) {
        $this->response = $response;
        $this->success = $success;
    }

}