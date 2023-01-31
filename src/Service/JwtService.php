<?php

namespace App\Service;

use App\Entity\User;
use Exception;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\Serializer;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class JwtService
{
    private const ALGORITHM_NAME = 'HS512';
    private const EXPIRES_IN = 3600;

    private const ISSUER = 'symfony-jwt-0';
    private const AUDIENCE = 'symfony-jwt-0';

    private readonly AlgorithmManager $algorithmManager;
    private readonly JWK $jwk;
    private readonly Serializer $serializer;

    public function __construct(ParameterBagInterface $parameterBag)
    {
        $this->algorithmManager = new AlgorithmManager([
            new HS512(),
        ]);

        $this->jwk = new JWK([
            'kty' => 'oct',
            'k' => $parameterBag->get('app.jwt_secret'),
        ]);

        $this->serializer = new CompactSerializer();
    }
    public function createTokenForUser(User $user): string
    {
        $jwsBuilder = new JWSBuilder($this->algorithmManager);

        $payload = json_encode([
            'user_id' => $user->getId(),
        ]);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($this->jwk, [
                'alg' => self::ALGORITHM_NAME,
                'iat' => time(),
                'nbf' => time(),
                'exp' => time() + self::EXPIRES_IN,
                'iss' => self::ISSUER,
                'aud' => self::AUDIENCE,
            ])
            ->build();

        return $this->serializer->serialize($jws, 0);
    }

    /**
     * @throws Exception
     */
    public function decodeToken(string $token): array
    {
        $jwsVerifier = new JWSVerifier($this->algorithmManager);

        $serializerManager = new JWSSerializerManager([$this->serializer]);
        $jws = $serializerManager->unserialize($token);
        $signatureIsVerified = $jwsVerifier->verifyWithKey($jws, $this->jwk, 0);

        if (!$signatureIsVerified) {
            throw new Exception('The provided signature is invalid.');
        }

        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker([self::ALGORITHM_NAME]),

                new IssuedAtChecker(protectedHeaderOnly: true),
                new NotBeforeChecker(protectedHeaderOnly: true),
                new ExpirationTimeChecker(protectedHeaderOnly: true),

                new IssuerChecker([self::ISSUER], protectedHeader: true),
                new AudienceChecker(self::AUDIENCE, protectedHeader: true),
            ],
            [
                new JWSTokenSupport()
            ]
        );

        $headerCheckerManager->check($jws, 0);

        $claims = json_decode($jws->getPayload(), true);

        $claimCheckerManager = new ClaimCheckerManager([
            // @todo: create custom claim checker for `roles`
            // @see: https://web-token.spomky-labs.com/the-components/claim-checker
        ]);

        $claimCheckerManager->check($claims, ['user_id']);

        return $claims;
    }
}