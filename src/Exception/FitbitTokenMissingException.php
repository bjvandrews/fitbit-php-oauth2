<?php

namespace brulath\fitbit\Exception;


class FitbitTokenMissingException extends LibraryException {
    protected $message = "Fitbit oauth token missing";
}
