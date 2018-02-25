<?php

namespace Esolitos\PwnedPasswords\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Esolitos\PwnedPasswords\PwnageValidator;

class PwnageValidatorTest extends TestCase {

  protected $http_client;

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
    // TODO
  }

  /**
   * @param string $hashed_password
   * @param array $expected_matches
   *
   * @dataProvider possibleHashMatchesProvider()
   */
  public function testFetchPossibleMatches(string $hashed_password, array $expected_matches, bool $is_valid = TRUE) {
    $guzzle_mock = new MockHandler([
      new Response(200, ['content-type'=>'text/plain; charset=utf-8'], implode("\r\n", $expected_matches))
    ]);
    $guzzle_stack = HandlerStack::create($guzzle_mock);
    $mock_client = new Client(['handler' => $guzzle_stack]);

    $pwnageValidator = new PwnageValidator();
    $pwnageValidator->withHttpClient($mock_client);
    $fetchPossibleMatchesMethod = $this->getAccessibleMethod('fetchPossibleMatches');

    if (!$is_valid) {
      $this->setExpectedException(\InvalidArgumentException::class, "Provided hash prefix is not valid: {$hashed_password}");
    }
    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, $hashed_password);

    $this->assertEquals($expected_matches, $returned_matches);
  }

  /**
   * Test a few expectable errors
   */
  public function testFailuresOnFetchPossibleMatches() {
    $guzzle_mock = new MockHandler([
      new Response(200, ['content-type' => 'text/plain; charset=utf-8'], "6F273C1493539AC19103C4FD0B9521FE95A:1\r\n"),
      new Response(404),
// TODO:      new Response(400, ['content-type' => 'text/plain; charset=utf-8'], "The hash prefix was not in a valid format"),
      new Response(429, ['Retry-After:' => '2'], "Rate limit exceeded, refer to acceptable use of the API: https://haveibeenpwned.com/API/v2#AcceptableUse"),
      new Response(500),
    ]);
    $guzzle_stack = HandlerStack::create($guzzle_mock);
    $mock_client = new Client(['handler' => $guzzle_stack]);

    $pwnageValidator = new PwnageValidator();
    $pwnageValidator->withHttpClient($mock_client);
    $fetchPossibleMatchesMethod = $this->getAccessibleMethod('fetchPossibleMatches');

    // 1st call: everything should be fine
    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, '8843D');
    $this->assertEquals(['6F273C1493539AC19103C4FD0B9521FE95A:1'], $returned_matches);

    // 2nd call: 404 = empty
    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, '8843D');
    $this->assertEmpty($returned_matches);

    // 3rd call: Should fail as it's an invalid hash prefix (too long)
//    $invalid_prefix = '8843DAA';
//    $this->setExpectedException(\InvalidArgumentException::class, "Server denoted an invalid hash prefix: {$invalid_prefix}");
//    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, $invalid_prefix);

    // 4th call: Http error 429: rate limited
    $this->setExpectedException(ClientException::class, "Rate limit exceeded, refer to acceptable use of the API: https://haveibeenpwned.com/API/v2#AcceptableUse", 429);
    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, '8843D');

    // 5th call: 500, ServerError is thrown
    $this->setExpectedException(ServerException::class);
    $returned_matches = $fetchPossibleMatchesMethod->invoke($pwnageValidator, '8843D');
    $this->assertEmpty($returned_matches);
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


  public function possibleHashMatchesProvider() {
    return [
      [ // 1234
        '7110E',
        [
          '0035F23D42DD69EB485362349534A15F8C3:2',
        ],
      ],

      [ // foobar
        '8843D',
        [
          '00B79B07EC9EC91C81ED5FA906AC7FA2411:3',
          '0117BA1E09C498E011A336638D1488160B3:1',
        ],
      ],
      [// lorem ipsum
        'BFB77',
        [
          '00DB8801F2BA0BD9F7F5136BB053A2043E7:10',
          '00DB8801F2BA0BD9F7F5136BB053A2043E7:10',
          '00DB8801F2BA0BD9F7F5136BB053A2043E7:10',
        ],
      ],
      [// ??
        '00000',
        [
          '3493F40E6139830004570508980074FBDEF:2',
          '34AD0A9279C77BBCCA6DC899D953755A8D5:2',
          '34B82F4B253D3AF7D26F92DF8C331DFA837:3',
        ],
      ],
      [// ??? ( A password. :) )
        'FFFFF',
        [
          // Empty result set
        ],
      ],
      [// non valid hash: not hex
        'HHHHH',
        [],
        false,
      ],
      [// non valid hash: to long
        '123456',
        [],
        false,
      ],
    ];
  }
}
