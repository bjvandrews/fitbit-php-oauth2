<?php

namespace brulath\fitbit\Exception;


class FitbitTokenExpiredException extends LibraryException {
    protected $message = "Fitbit oauth token expired";
}
