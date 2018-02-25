<?php

namespace Esolitos\PwnedPasswords\Tests;

use PHPUnit\Framework\TestCase;
use Esolitos\PwnedPasswords\PwnageValidator;

class PwnageValidatorTest extends TestCase {

  /**
   * @param string $methodName
   *
   * @return \ReflectionMethod
   * @throws \ReflectionException
   */
  protected function getAccessibleMethod(string $methodName) {
    $class = new \ReflectionClass(PwnageValidator::class);
    $method = $class->getMethod($methodName);

    if (!$method->isPublic()) {
      $method->setAccessible(TRUE);
    }

    return $method;
  }

  public function testGetPasswordPwnage() {

  }

  public function testFetchPossibleMatches() {

  }

  public function testGetHashPrefixFromHash() {

  }

  /**
   * @param string $plaintext
   * @param string $expected_hash
   *
   * @dataProvider plaintextAndHashProvider()
   *
   * @throws \ReflectionException
   */
  public function testGetUpperHash(string $plaintext, string $expected_hash) {
    $pwnageValidator = new PwnageValidator();
    $method = $this->getAccessibleMethod('getUpperHash');

    $result_hash = $method->invoke($pwnageValidator, $plaintext);

    $this->assertEquals($expected_hash, $result_hash);
  }


  /**
   * Provider of plaintext with respective hashes.
   */
  public function plaintextAndHashProvider() {
    return [
      ['1234', '1BE168FF837F043BDE17C0314341C84271047B31'],
      ['foobar', '988881adc9fc3655077dc2d4d757d480b5ea0e11'],
      ['lorem ipsum', '1d9616855a130da2cd0665f79139f6d7853595b1'],
      ['p@ssword', '35a90e0e7af38a53156d71b453d332cf2ad3dd73'],
    ];
  }
}
