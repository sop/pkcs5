<?php

namespace Sop\PKCS5\HashFunc;

/**
 * MD2 hash function.
 */
class MD2 extends HashFunc
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
        return hash("md2", $data, true);
    }
}
