<?php

namespace brulath\fitbit;


class FitbitTokenMissingException extends FitbitException {
    protected $message = "Fitbit oauth token missing";
}
