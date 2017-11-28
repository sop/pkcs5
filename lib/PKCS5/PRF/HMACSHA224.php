<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PRF;

/**
 * Implements HMAC-SHA-224 as a pseudorandom function.
 */
class HMACSHA224 extends HMACPRF
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 28;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return "sha224";
    }
}
