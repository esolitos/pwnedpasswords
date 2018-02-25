<?php

namespace Esolitos\PwnedPasswords;


use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;

class PwnageValidator implements PwnageValidatorInterface {

  const PWNED_PASS_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

  /** @var \GuzzleHttp\ClientInterface  */
  protected $httpClient;

  /** @var array */
  protected $httpOptions;

  public function __construct() {
    $this->httpClient = new Client();

    $this->httpOptions = [
      'timeout'     => 2,
      'headers'     => [
        'User-Agent' => 'esolitos/pwnedpassword library - https://packagist.org/packages/esolitos/pwnedpasswords',
      ],
    ];
  }

  /**
   * Overrides default http client
   *
   * @param \GuzzleHttp\ClientInterface $client
   *
   * @return $this
   */
  public function withHttpClient(ClientInterface $client) {
    $this->httpClient = $client;

    return $this;
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
    $possible_matches = [];
    $uri = self::PWNED_PASS_ENDPOINT.$hash_prefix;

    if (!preg_match('/^[0-9A-F]{5}$/i', $hash_prefix)) {
      throw new \InvalidArgumentException("Provided hash prefix is not valid: {$hash_prefix}");
    }

    try {
      $response = $this->httpClient->get($uri, $this->httpOptions);

      if ($response->getStatusCode() == 200) {
        $body = $response->getBody();
        $answer = $body->isReadable() ? $body->getContents() : '';

        // Split the answer on new-line characters.
        $possible_matches = preg_split('/\\r\\n|\\r|\\n/', $answer);
      }
    } catch (ClientException $exception) {
      if ($exception->getCode() == 400) {
        // 400 Error denotes an invalid prefix
        throw new \InvalidArgumentException("Server denoted an invalid hash prefix: {$hash_prefix}");
      }
      elseif ($exception->getCode() == 404) {
        // Not found should not happen, however it doesn't indicate an error, but simply an empty result.
        // TODO: Add logging.
      }
      else {
        // Forward it if it's not an "expectable" exception.
        throw $exception;
      }
    }

    return array_filter($possible_matches);
  }
}