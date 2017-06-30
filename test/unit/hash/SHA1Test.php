<?php
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\SHA1;

/**
 * @group pbe
 * @group hash
 */
class PBESHA1Test extends PHPUnit_Framework_TestCase
{
    /**
     *
     * @return HashFunc
     */
    public function testCreate()
    {
        $func = new SHA1();
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
        $this->assertEquals(20, $func->length());
    }
    
    /**
     * @depends testCreate
     *
     * @param HashFunc $func
     */
    public function testHash(HashFunc $func)
    {
        static $data = "DATA";
        $expected = sha1($data, true);
        $this->assertEquals($expected, $func($data));
    }
}
