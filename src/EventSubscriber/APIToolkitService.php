<?php

namespace APIToolkit\EventSubscriber;

use Google\Auth\Cache\TypedItem;
use Google\Auth\Cache\MemoryCacheItemPool;
use Google\Cloud\PubSub\PubSubClient;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use JsonPath\JsonObject;
use JsonPath\InvalidJsonException;

class APIToolkitService implements EventSubscriberInterface
{
  private const CACHE_KEY = 'apitoolkitInstance';
  private CacheItemPoolInterface $cachePool;
  private array $credentials = [];
  private \SplObjectStorage $startTimes;

  public function __construct(
    private string $apiKey,
    private array $redactHeaders = [],
    private array $redactRequestBody = [],
    private array $redactResponseBody = [],
    private string $rootURL = 'https://app.apitoolkit.io',
    private bool $captureRequestBody = false,
    private bool $captureResponseBody = false,
  ) {
    $this->startTimes = new \SplObjectStorage();
    $this->cachePool = new MemoryCacheItemPool();
  }

  public function setCachePool(CacheItemPoolInterface $cachePool): void
  {
    $this->cachePool = $cachePool;
  }

  public static function getSubscribedEvents(): array
  {
    return [
      KernelEvents::REQUEST => [
        ['onKernelRequestPre', 10],
      ],
      KernelEvents::RESPONSE => [
        ['onKernelResponsePre', 10],
      ],
    ];
  }

  public function onKernelRequestPre(RequestEvent $event): void
  {
    $this->startTimes[$event->getRequest()] = hrtime(true);
  }

  public function onKernelResponsePre(ResponseEvent $event): void
  {
    $credentials = $this->getCredentials();
    // No credentials available, so there's no need continuing with apitoolkit logging.
    if (!$credentials) {
      return;
    }
    if (!$this->startTimes->contains($event->getRequest())) {
      return;
    }

    $payload = $this->buildPayload(
      $event->getRequest(),
      $event->getResponse(),
      $this->startTimes[$event->getRequest()],
      $credentials['project_id']
    );
    $this->publishMessage($payload, $credentials);
  }

  // payload static method deterministically converts a request, response object, a start time and a projectId
  // into a pauload json object which APIToolkit server is able to interprete.
  public function buildPayload(Request $request, $response, $startTime, $projectId)
  {
    return [
      'duration' => round(hrtime(true) - $startTime),
      'host' => $request->getHttpHost(),
      'method' => $request->getMethod(),
      'project_id' => $projectId,
      'proto_major' => 1,
      'proto_minor' => 1,
      'query_params' => $request->query->all(),
      'path_params' => $request->attributes->get('_route_params'),
      'raw_url' => $request->getRequestUri(),
      'referer' => $request->headers->get('referer', ''),
      'request_headers' => $this->redactHeaderFields($this->redactHeaders, $request->headers->all()),
      'response_headers' => $this->redactHeaderFields($this->redactHeaders, $response->headers->all()),
      'request_body' => $this->captureRequestBody ? base64_encode($this->redactJSONFields($this->redactRequestBody, $request->getContent())) : '',
      'response_body' => $this->captureResponseBody ? base64_encode($this->redactJSONFields($this->redactResponseBody, $response->getContent())) : '',
      'sdk_type' => 'PhpSymfony',
      'status_code' => $response->getStatusCode(),
      'timestamp' => (new \DateTime())->format('c'),
      'url_path' => $request->attributes->get('_route'),
    ];
  }

  // publishMessage leverages the credentials object to build a google pubsub topic
  // and then use that pubsub topic to publish a message into the APIToolkit pubsub queue.
  public function publishMessage($payload, $credentials): void
  {
    $pubsubClient = new PubSubClient(
      [
        'keyFile' => $credentials['pubsub_push_service_account']
      ]
    );
    $topic = $pubsubClient->topic($credentials['topic_id']);
    if (!$topic) {
      return;
    }

    $topic->publish(
      [
        'data' => \json_encode($payload, JSON_UNESCAPED_SLASHES)
      ]
    );
  }

  public function getCredentials(): array
  {
    if ($this->credentials) {
      return $this->credentials;
    }

    if ($this->cachePool->hasItem(self::CACHE_KEY)) {
      $cacheResult = $this->cachePool->getItem(self::CACHE_KEY)->get();
      if (is_array($cacheResult)) {
        $this->credentials = $cacheResult;
      }
    }

    if (!$this->credentials) {
      $url = $this->rootURL . "/api/client_metadata";

      $curlInit = \curl_init($url);
      \curl_setopt($curlInit, CURLOPT_URL, $url);
      \curl_setopt($curlInit, CURLOPT_RETURNTRANSFER, true);

      $headers = array(
        'Authorization: Bearer ' . $this->apiKey,
      );

      \curl_setopt($curlInit, CURLOPT_HTTPHEADER, $headers);

      $curlResponse = \curl_exec($curlInit);
      if ($curlResponse == false) {
        \curl_error($curlInit);
      } else {
        $this->credentials = \json_decode($curlResponse, true);
        $cacheItem = new TypedItem(self::CACHE_KEY);
        $cacheItem->set($this->credentials);
        $cacheItem->expiresAfter(2000);
        $this->cachePool->saveDeferred($cacheItem);
      }

      \curl_close($curlInit);
    }

    return $this->credentials;
  }

  public function redactHeaderFields(array $redactKeys, array $headerFields): array
  {
    array_walk($headerFields, function (&$value, $key, $redactKeys) {
      if (in_array(strtolower($key), array_map('strtolower', array_merge($redactKeys, ['authorization', 'cookie', 'set-cookie', 'proxy-authorization'])))) {
        $value = ['[CLIENT_REDACTED]'];
      }
    }, $redactKeys);
    return $headerFields;
  }

  // redactJSONFields accepts a list of jsonpath's to redact, and a json object to redact from, 
  // and returns the final json after the redacting has been done.
  public function redactJSONFields(array $redactKeys, string $jsonStr): string
  {
    try {
      $obj = new JsonObject($jsonStr);
    } catch (InvalidJsonException $e) {
      // For any data that isn't json, we simply return the data as is.
      return $jsonStr;
    }

    foreach ($redactKeys as $jsonPath) {
      $obj->set($jsonPath, '[CLIENT_REDACTED]');
    }
    return $obj->getJson();
  }
}
