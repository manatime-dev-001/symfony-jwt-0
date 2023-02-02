<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use Exception;
use Nelmio\ApiDocBundle\Annotation\Model;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use OpenApi\Attributes as OA;

class ApiLoginController extends AbstractController
{
    public const JWT_COOKIE_NAME = 'auth-jwt';

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    #[OA\Response(
        content: new OA\JsonContent(ref: new Model(type: User::class)),
        response: 200,
        description: 'login here'
    )]
    #[OA\RequestBody()]
//    #[OA\Response(
//        response: Response::HTTP_OK,
//        description: "Returns the user's data and token, and an auth-jwt cookie>",
//        content: new OA\JsonContent(
//            type: 'array',
//            items: []
//        )
//    )]
//    #[OA\Post(
//        path: "/login",
//        description: "Logs in a user if the correct credentials are provided, and returns a `auth-jwt` cookie - for subsequent authentication attempts.",
//        summary: "Logs in a user.",
//        operationid: "login",
//        tags: ['user'],
//        parameters: [
//            new OA\Parameter(name: "username", required: true)
//        ],
//        responses: [
//            new OA\Response(response: 200, description: 'OK')
//        ]
//    )]
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
}
