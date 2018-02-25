<?php

namespace Esolitos\PwnedPasswords;


interface PwnageValidatorInterface {

  /**
   * Gets the number of times a single password has been found in breaches.
   *
   * @param string $plaintext_password
   *
   * @return int
   */
  public function getPasswordPwnage(string $plaintext_password): int;
}