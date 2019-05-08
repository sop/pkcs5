<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PRF;

/**
 * Base class for HMAC based pseudorandom functions.
 */
abstract class HMACPRF extends PRF
{
    /**
     * {@inheritdoc}
     */
    public function compute(string $arg1, string $arg2): string
    {
        return hash_hmac($this->_hashAlgo(), $arg2, $arg1, true);
    }

    /**
     * Get the name of the hash algorithm supported by hash_hmac.
     *
     * @return string
     */
    abstract protected function _hashAlgo(): string;
}
