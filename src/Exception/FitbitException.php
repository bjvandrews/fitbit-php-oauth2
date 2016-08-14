<?php

namespace brulath\fitbit\Exception;


class FitbitException extends \Exception {
    protected $message = "Fitbit Exception: ";
    protected $success = false;
    protected $errors = [];

    /**
     * @param int $code
     * @param boolean $success
     * @param array|string $errors Fitbit error array
     */
    public function __construct($code, $success, $errors)
    {
        $this->success = $success;
        $this->errors = $errors;
        $message = "Fitbit {$code} ({$success}): " . json_encode($errors);

        parent::__construct($message, $code);
    }
}
