<?php

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\MD2;

/**
 * @group pbe
 * @group hash
 */
class PBEMD2Test extends TestCase
{
    /**
     *
     * @return HashFunc
     */
    public function testCreate()
    {
        $func = new MD2();
        $this->assertInstanceOf(HashFunc::class, $func);
        return $func;
    }
    
    /**
     * @depends testCreate
     *
     * @param HashFunc $func
     */
    public function testLength(HashFunc $func)
    {
        $this->assertEquals(16, $func->length());
    }
    
    /**
     * @depends testCreate
     *
     * @param HashFunc $func
     */
    public function testHash(HashFunc $func)
    {
        static $data = "DATA";
        $expected = hash("md2", $data, true);
        $this->assertEquals($expected, $func($data));
    }
}
