<?php

namespace APIToolkit\EventSubscriber;

use PHPUnit\Framework\TestCase;
use APIToolkit\EventSubscriber;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class APIToolkitServiceTest extends TestCase
{
  /** @var EventDispatcher **/
  private $dispatcher;

  private $testJSON = '
{ "store": {
    "book": [
      { "category": "reference",
        "author": "Nigel Rees",
        "title": "Sayings of the Century",
        "price": 8.95,
        "available": true
      },
      { "category": "fiction",
        "author": "Evelyn Waugh",
        "title": "Sword of Honour",
        "price": 12.99,
        "available": false
      }
    ],
    "bicycle": {
      "color": "red",
      "price": 19.95,
      "available": true
    }
  },
  "authors": [
    "Nigel Rees",
    "Herman Melville",
    "J. R. R. Tolkien"
  ]
}
';

  public function setUp(): void
  {
    // $this->dispatcher = new EventDispatcher();
  }
  public function test_empty_redected_json_same_as_input(): void
  {
    $svc = new APIToolkitService("");
    $redactedJSON = $svc->redactJSONFields([], $this->testJSON);
    $this->assertJsonStringEqualsJsonString($this->testJSON, $redactedJSON);
  }

  public function test_redacted_field(): void
  {
    $testJSON = '
    { "store": {
        "book": [
          { "category": "reference",
            "author": "Nigel Rees",
            "title": "Sayings of the Century",
            "price": 8.95,
            "available": true
          },
          { "category": "fiction",
            "author": "Evelyn Waugh",
            "title": "Sword of Honour",
            "price": 12.99,
            "available": false
          }
        ]
      }
    }
    ';
    $expectedJSON = '{ "store": {"book": "[CLIENT_REDACTED]"}}';
    $svc = new APIToolkitService("");
    $redactedJSON = $svc->redactJSONFields(['$.store.book'], $testJSON);
    $this->assertJsonStringEqualsJsonString($expectedJSON, $redactedJSON);
  }

  public function test_redacted_array_subfield(): void
  {
    $testJSON = '
    { "store": {
        "book": [
          { "category": "reference",
            "author": "Nigel Rees"
          },
          { "category": "fiction",
            "author": "Evelyn Waugh"
          }
        ]
      }
    }
    ';
    $expectedJSON = '
    { "store": {
        "book": [
          { "category": "[CLIENT_REDACTED]",
            "author": "Nigel Rees"
          },
          { "category": "[CLIENT_REDACTED]",
            "author": "Evelyn Waugh"
          }
        ]
      }
    }
    ';
    $svc = new APIToolkitService("");
    $redactedJSON = $svc->redactJSONFields(['$.store.book[*].category'], $testJSON);
    $this->assertJsonStringEqualsJsonString($expectedJSON, $redactedJSON);
  }

  public function test_redacts_sensitive_headers_by_default(): void
  {
    $request = Request::create('/login', 'POST', [], [], [], [
      'HTTP_AUTHORIZATION' => 'Bearer abc',
      'HTTP_COOKIE' => 'sid=1',
      'HTTP_PROXY_AUTHORIZATION' => 'Basic x',
      'HTTP_X_API_KEY' => 'key',
      'HTTP_ACCEPT' => 'text/plain',
    ]);
    $response = new Response('ok', 200, ['Set-Cookie' => 'sid=2']);
    $payload = (new APIToolkitService("", ['X-Api-Key']))->buildPayload($request, $response, hrtime(true), 'pid');
    foreach (['authorization', 'cookie', 'proxy-authorization', 'x-api-key'] as $h) {
      $this->assertSame(['[CLIENT_REDACTED]'], $payload['request_headers'][$h], $h);
    }
    $this->assertSame(['[CLIENT_REDACTED]'], $payload['response_headers']['set-cookie']);
    $this->assertSame(['text/plain'], $payload['request_headers']['accept']);
  }

  public function test_bodies_are_not_captured_by_default(): void
  {
    $request = Request::create('/login', 'POST', [], [], [], [], '{"user":"u"}');
    $response = new Response('{"token":"t"}');
    $payload = (new APIToolkitService(""))->buildPayload($request, $response, hrtime(true), 'pid');
    $this->assertSame('', $payload['request_body']);
    $this->assertSame('', $payload['response_body']);

    $svc = new APIToolkitService("", redactRequestBody: ['$.user'], captureRequestBody: true, captureResponseBody: true);
    $payload = $svc->buildPayload($request, $response, hrtime(true), 'pid');
    $this->assertJsonStringEqualsJsonString('{"user":"[CLIENT_REDACTED]"}', base64_decode($payload['request_body']));
    $this->assertJsonStringEqualsJsonString('{"token":"t"}', base64_decode($payload['response_body']));
  }

  public function test_credentials_fetch_rejects_untrusted_certificate(): void
  {
    // A local HTTPS server with a self-signed certificate that would hand out credentials.
    $server = <<<'PHP'
      $key = openssl_pkey_new();
      $cert = openssl_csr_sign(openssl_csr_new(['commonName' => '127.0.0.1'], $key), null, $key, 1);
      openssl_x509_export($cert, $pem); openssl_pkey_export($key, $keyPem);
      $file = tempnam(sys_get_temp_dir(), 'cert'); file_put_contents($file, $pem . $keyPem);
      $srv = stream_socket_server('tls://127.0.0.1:0', $e, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
        stream_context_create(['ssl' => ['local_cert' => $file]]));
      echo parse_url(stream_socket_get_name($srv, false), PHP_URL_PORT), "\n";
      if ($c = @stream_socket_accept($srv, 5)) {
        fread($c, 4096);
        fwrite($c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"project_id\":\"leak\"}");
        fclose($c);
      }
      unlink($file);
      PHP;
    $proc = proc_open([PHP_BINARY, '-r', $server], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    try {
      $port = (int) fgets($pipes[1]);
      $this->assertGreaterThan(0, $port);
      $this->assertSame([], (new APIToolkitService("key", rootURL: "https://127.0.0.1:$port"))->getCredentials());
    } finally {
      proc_terminate($proc);
      proc_close($proc);
    }
  }

  public function test_return_invalid_json_as_is(): void
  {
    $testJSON = 'invalid_json';
    $expectedJSON = 'invalid_json';
    $svc = new APIToolkitService("");
    $redactedJSON = $svc->redactJSONFields(['$.store.book[*].category'], $testJSON);
    $this->assertEquals($expectedJSON, $redactedJSON);
  }
}
