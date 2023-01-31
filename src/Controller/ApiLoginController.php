<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use Exception;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiLoginController extends AbstractController
{
    public const JWT_COOKIE_NAME = 'auth-jwt';

    #[Route('/api/login', name: 'api_login')]
    public function login(JwtService $jwtService, ParameterBagInterface $parameterBag): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        if (is_null($user)) {
            return $this->json([
                'message' => 'invalid credentials',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $token = $jwtService->createTokenForUser($user);

        $response = new JsonResponse([
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getUserIdentifier(),
            ],
            'token' => $jwtService->createTokenForUser($user),
        ], Response::HTTP_OK);

        $jwtCookie = Cookie::create(self::JWT_COOKIE_NAME)
            ->withValue($token)
            ->withExpires(time() + intval($parameterBag->get('app.jwt_lifetime')))
            ->withHttpOnly()
            ->withSecure();

        $response->headers->setCookie($jwtCookie);

        return $response;
    }

    #[Route('/api/verify/{token}')]
    public function verify(string $token, JwtService $jwtService): JsonResponse
    {
        try {
            $claims = $jwtService->decodeToken($token);
        } catch (Exception $exception) {
            return $this->json([
                'status' => 'FAILED',
                'error' => $exception
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json($claims);
    }
}
