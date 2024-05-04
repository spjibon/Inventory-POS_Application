<?php

namespace App\Http\Controllers;

use App\Helper\JWTToken;
use App\Mail\OTPMail;
use App\Models\User;
use Exception;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;
class UserController extends Controller
{
    function LoginPage():View{
        return view('pages.auth.login-page');
    }

    function RegistrationPage():View{
        return view('pages.auth.registration-page');
    }
    function SendOtpPage():View{
        return view('pages.auth.send-otp-page');
    }
    function VerifyOTPPage():View{
        return view('pages.auth.verify-otp-page');
    }

    function ResetPasswordPage():View{
        return view('pages.auth.reset-pass-page');
    }

    function ProfilePage():View{
        return view('pages.dashboard.profile-page');
    }


    // User Registration Using Try And Catch /*
    function UserRegistration(Request $request)
    {
        try {
            User::create([
                'firstName' => $request->input('firstName'),
                'lastName' => $request->input('lastName'),
                'email' => $request->input('email'),
                'mobile' => $request->input('mobile'),
                'password' => $request->input('password'),
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'User Registration Successfully'
            ], 200);
        }
        catch (Exception $e) {
            return response()->json([
                'status' => 'failed',
                'message' => 'User Registration failed',
                //'message' => $e->getMessage()
            ], 200);
        }
    }


    // User LogIn

    function UserLogin(Request $request)
    {
        $count = User::where('email', '=', $request->input('email'))
            ->where('password', '=', $request->input('password'))
            ->select('id')->first();

        if ($count !== null) {
            // User login->JWT Issue

            $token = JWTToken::CreateToken($request->input('email'),$count->id);
            return response()->json([
                'status' => 'success',
                'message' => 'User Login Successful',
            ], 200)->cookie('token',$token,60*24*30);
        } else {
            return response()->json([
                'status' => 'failed',
                'message' => 'Unauthorised',
            ], 200);
        }
    }

    // OTP Code Sending

    function SendOTPCode(Request $request)
    {
        $email = $request->input('email');
        $otp = rand(1000, 9999);
        $count = User::where('email','=',$email)->count();

        if ($count == 1) {
            // Then Send Email With OTP
            Mail::to($email)->send(new OTPMail($otp));
            // OTP Code Table Update In Database
           User::where('email','=',$email)->update(['otp'=>$otp]);
            return response()->json([
                'status' => 'success',
                'message' => '4 Digit OTP Code Has Been Send Your Email '
            ], 200);
        } else {
            return response()->json([
                'status' => 'failed',
                'message' => 'Unauthorised',
            ]);
        }
    }

    // Verify OTP

    function VerifyOTP(Request $request)
    {
        $email=$request->input('email');
        $otp=$request->input('otp');
        $count=User::where('email','=',$email)
            ->Where('otp','=',$otp)->count();

        if ($count==1){

            // Database OTP Update

            User::where('email','=',$email)->update(['otp'=>'0']);

            // Password Reset Token Issue and With Using Middleware

            $token = JWTToken::CreateTokenForSetPassword($request->input('email'));
            return response()->json([
                'status' => 'success',
                'message' => 'OTP Verification Successful',
               // 'token' => $token
            ], 200)->cookie('token',$token,60*24*30);
        }
        else{
            return response()->json([
                'status' => 'failed',
                'message' => 'Unauthorised',
            ], 200);
        }
    }

    // Reset Password

    function ResetPassword(Request $request)
    {
        try {
            $email=$request->header('email');
            $password=$request->input('password');
            User::where('email','=',$email)->update(['password'=>$password]);
            return response()->json([
                'status' => 'success',
                'message' => 'Password Reset Successfully'
            ], 200);
        }
        catch (Exception $e){
            return response()->json([
                'status' => 'failed',
                'message' => 'Request failed ! Something Wrong ',
                //'message' => $e->getMessage()
            ], 200);
        }

    }

    // User Logout
    function UserLogout(){
        return redirect('/userLogin')->cookie('token','',-1);
    }
    // User Profile

    function UserProfile(Request $request){
      $email=$request->header('email');
      $user=User::where('email','=',$email)->first();
      return response()->json([
        'status'=>'success',
        'message'=>'Request Successful',
        'data'=>$user
      ],200);
    }

    // Update User Profile

    function UpdateProfile(Request $request){
        
    try{
      
      $email=$request->header('email');
      $firstName=$request->input('firstName');
      $lastName=$request->input('lastName');
      $mobile=$request->input('mobile');
      $password=$request->input('password');
      
      User::where('email','=',$email)->update([
        'firstName'=>$firstName,
        'lastName'=>$lastName,
        'mobile'=>$mobile,
        'password'=>$password
      ]);
      return response()->json([
        'status'=>'success',
        'message'=>'Request Successful',
      ],200);

    }catch(Exception $e){
        return response()->json([
            'status'=>'fail',
            'message'=>'Something Went Wrong',
        ],200);
    }
    }

}
