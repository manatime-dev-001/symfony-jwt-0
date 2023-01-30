<?php

namespace App\Controller;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class JwtController extends AbstractController
{
    public const JWT_KEY = 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g';

    #[Route('/jwt', name: 'app_jwt', methods: ['GET'])]
    public function getToken(): JsonResponse
    {
        $algorithmManager = new AlgorithmManager([
            new HS256(),
        ]);

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => self::JWT_KEY,
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $payload = json_encode([
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600,
            'iss' => 'symfony-jwt-0-issuer',
            'aud' => 'symfony-jwt-0-consumer',
        ]);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => 'HS256'])
            ->build();

        $serializer = new CompactSerializer();

        $token = $serializer->serialize($jws, 0);

        return $this->json([
            'token' => $token,
        ]);
    }

    #[Route('/jwt/{token}', methods: ['GET'])]
    public function decodeToken(string $token): JsonResponse
    {
        $algorithmManager = new AlgorithmManager([new HS256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        // @todo: check header parameters here

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => self::JWT_KEY,
        ]);

        $serializerManager = new JWSSerializerManager([new CompactSerializer()]);

        $jws = $serializerManager->unserialize($token);

        $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

        $payload = json_decode($jws->getPayload());

        return $this->json([
            'token' => $token,
            'isVerified' => $isVerified,
            'payload' => $payload,
        ]);
    }
}
