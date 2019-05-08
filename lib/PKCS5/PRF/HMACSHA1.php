<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PRF;

/**
 * Implements HMAC-SHA-1 as a pseudorandom function.
 *
 * @see https://tools.ietf.org/html/rfc2898#appendix-B.1.1
 */
class HMACSHA1 extends HMACPRF
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 20;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha1';
    }
}
