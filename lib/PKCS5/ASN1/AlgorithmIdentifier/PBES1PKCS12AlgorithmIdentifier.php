<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

/**
 * Base class for PBES1 encryption scheme with PKCS #12 semantics.
 *
 * @todo Implement
 */
abstract class PBES1PKCS12AlgorithmIdentifier extends PBES1AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt Salt
     * @param int $iteration_count Iteration count
     * @throws \UnexpectedValueException
     */
    public function __construct($salt, $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
    }
}
