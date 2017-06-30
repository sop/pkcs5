<?php

namespace Sop\PKCS5\HashFunc;

/**
 * SHA1 hash function.
 */
class SHA1 extends HashFunc
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 20;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function hash($data)
    {
        return sha1($data, true);
    }
}
