<?php

namespace App\Helper;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use function Symfony\Component\Translation\t;

class JWTToken
{
    // JWT Token Create And Encode
   public static function CreateToken($userEmail,$userID):string
   {
      $key= env('JWT_KEY');
      $payload=[
          'iss'=>'laravel-token',
          'iat'=>time(),
          'exp'=>time()+60*60,
          'userEmail'=>$userEmail,
          'userID'=>$userID

      ];
      return JWT::encode($payload,$key,'HS256');
   }
   // JWT Token Verify And Decode
   public static function VerifyToken($token):string|object 
   {
       try {
          if($token==null){
            return 'unauthorized';
          }
          else{
            $key= env('JWT_KEY');
            $decode=JWT::decode($token,new Key($key,'HS256'));
            return $decode;
          }
          
       }
       catch (Exception $e){
          return 'unauthorized';
       }

   }
    // JWT Token Create For Set Password
    public static function CreateTokenForSetPassword($userEmail):string
    {
        $key= env('JWT_KEY');
        $payload=[
            'iss'=>'laravel-token',
            'iat'=>time(),
            'exp'=>time()+60*20,
            'userEmail'=>$userEmail,
            'userID'=>'0'

        ];
        return JWT::encode($payload,$key,'HS256');
    }
}
