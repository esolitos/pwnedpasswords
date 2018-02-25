<?php

namespace Esolitos\PwnedPasswords;


use GuzzleHttp\Client;

class PwnageValidator implements PwnageValidatorInterface {

  const PWNED_PASS_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

  /** @var \GuzzleHttp\Client  */
  protected $httpClient;

  /** @var array */
  protected $httpOptions;

  public function __construct() {
    $this->httpClient = new Client();

    $this->httpOptions = [
      'http_errors' => FALSE,
      'timeout'     => 2,
      'headers'     => [
        // TODO
        'User-Agent' => $_SERVER['SERVER_NAME'] . ' via PwnedPassword on Drupal 8 - https://drupal.org/project/pwned_password',
      ],
    ];
  }

  public function getPasswordPwnage(string $plaintext_password): int {
    $pwnageLevel = 0;
    // Calculate sha1 and get prefix for it.
    $hashedPassword = $this->getUpperHash($plaintext_password);
    $hashPrefix = $this->getHashPrefixFromHash($hashedPassword);

    // Fetch all partial matches
    $allPartialMatches = $this->fetchPossibleMatches($hashPrefix);
    foreach ($allPartialMatches as $partialMatch) {
      // Split the partial hash match and the match count
      list($testHash, $marchesCount) = explode(':', $possible_match);

      if ($hashedPassword === "{$hashPrefix}{$testHash}") {
        $pwnageLevel = $count;
        break;
      }
    }

    return $pwnage_level;
  }

  /**
   * Generates the UPPERCASE sha1 hash of a given plaintext password.
   *
   * @param string $plaintext_password
   *
   * @return string
   */
  protected function getUpperHash(string $plaintext_password): string {
    return strtoupper(
      hash('sha1', $plaintext_password)
    );
  }

  /**
   * Returns the prefix of a hashed password.
   *
   * @param string $hash
   *
   * @return string
   *   Hash prefix of 5 char length
   */
  protected function getHashPrefixFromHash(string $hash): string {
    return substr($hash, 0, 5);
  }


  /**
   * Queries PwnedPasswords.com service and splits the answer in lines.
   *
   * @param string $hash_prefix
   *  Hashed password prefix, as returned by ::getUpperHash and ::getHashPrefixFromHash
   *
   * @return string[]
   *   All possible matches and results, separated by a column.
   */
  protected function fetchPossibleMatches(string $hash_prefix): array {
    $uri = self::PWNED_PASS_ENDPOINT.$hash_prefix;
    $response = $this->httpClient->get($uri,$this->httpOptions);

    $body = $response->getBody();
    $answer = $body->isReadable() ? $body->getContents() : '';

    // Split the answer on new-line characters.
    return (array) preg_split('/\\r\\n|\\r|\\n/', $answer);
  }
}