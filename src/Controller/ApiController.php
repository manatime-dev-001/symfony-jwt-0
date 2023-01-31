<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use Exception;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ApiController extends AbstractController
{
    #[Route('/api/verify/{token}', methods: ['GET'])]
    public function verifyToken(string $token, JwtService $jwtService): JsonResponse
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

    #[Route('/api/user', methods: ['GET'])]
    public function getUserData(): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        return $this->json([
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
                'password' => $user->getPassword(),
                'roles' => $user->getRoles(),
            ],
        ]);
    }
}
