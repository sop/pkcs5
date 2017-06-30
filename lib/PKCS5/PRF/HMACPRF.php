<?php

namespace Sop\PKCS5\PRF;

/**
 * Base class for HMAC based pseudorandom functions.
 */
abstract class HMACPRF extends PRF
{
    /**
     * Get the name of the hash algorithm supported by hash_hmac.
     *
     * @return string
     */
    abstract protected function _hashAlgo();
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function compute($arg1, $arg2)
    {
        return hash_hmac($this->_hashAlgo(), $arg2, $arg1, true);
    }
}
