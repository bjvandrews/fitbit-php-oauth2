<?php

namespace brulath\fitbit;


class FitbitTokenExpiredException extends FitbitException {
    protected $message = "Fitbit oauth token expired";
}