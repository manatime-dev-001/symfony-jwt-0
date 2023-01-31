<?php

namespace Lib\Jwt\ClaimChecker;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class UserIdClaimChecker implements ClaimChecker
{
    public function __construct(private readonly EntityManagerInterface $entityManager)
    {
        //
    }

    /**
     * @throws InvalidClaimException
     */
    public function checkClaim(mixed $value): void
    {
        if (!is_numeric($value)) {
            throw new InvalidClaimException("The claim '{$this->supportedClaim()}' must be numeric.", $this->supportedClaim(), $value);
        }

        // @important: this makes an additional database trip for every request.
        if (!$this->entityManager->getRepository(User::class)->find($value)) {
            throw new InvalidClaimException("The user with id '{$value}' does not exist.", $this->supportedClaim(), $value);
        }
    }

    public function supportedClaim(): string
    {
        return 'user_id';
    }
}