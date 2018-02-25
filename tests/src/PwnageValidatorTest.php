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
      ['1234', '7110EDA4D09E062AA5E4A390B0A572AC0D2C0220'],
      ['foobar', '8843D7F92416211DE9EBB963FF4CE28125932878'],
      ['lorem ipsum', 'BFB7759A67DAEB65410490B4D98BB9DA7D1EA2CE'],
      ['p@ssword', '36E618512A68721F032470BB0891ADEF3362CFA9'],
    ];
  }
}
