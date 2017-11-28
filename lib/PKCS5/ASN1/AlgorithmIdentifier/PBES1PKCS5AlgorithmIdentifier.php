<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

/**
 * Base class for PBES1 encryption scheme with PKCS #5 semantics.
 */
abstract class PBES1PKCS5AlgorithmIdentifier extends PBES1AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt Salt
     * @param int $iteration_count Iteration count
     * @throws \UnexpectedValueException
     */
    public function __construct(string $salt, int $iteration_count)
    {
        if (strlen($salt) !== 8) {
            throw new \UnexpectedValueException("Salt length must be 8 octets.");
        }
        parent::__construct($salt, $iteration_count);
    }
}
