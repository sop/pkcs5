<?php

namespace Sop\PKCS5\HashFunc;

/**
 * MD5 hash function.
 */
class MD5 extends HashFunc
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 16;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function hash($data)
    {
        return md5($data, true);
    }
}
