<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PRF;

/**
 * Implements HMAC-SHA-256 as a pseudorandom function.
 */
class HMACSHA256 extends HMACPRF
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 32;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return "sha256";
    }
}
