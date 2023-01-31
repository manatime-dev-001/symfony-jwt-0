<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiLoginController extends AbstractController
{
    #[Route('/api/login', name: 'api_login')]
    public function index(JwtService $jwtService): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        if (is_null($user)) {
            return $this->json([
                'message' => 'invalid credentials',
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json([
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getUserIdentifier(),
            ],
            'token' => $jwtService->createTokenForUser($user),
        ]);
    }
}
