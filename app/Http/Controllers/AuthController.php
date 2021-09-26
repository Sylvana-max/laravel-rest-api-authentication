<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Redis;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('mytoken')->plainTextToken;
        $response = [
            'user' =>$user,
            'token' => $token
        ];

        return response($response, 201);
    }

    //Login
    public function login(Request $request){
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //Check for email
        $user = User::where('email', $fields['email'])->first();

        //Check for password
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response(['message' => 'Invalid Credentials'], 401);
        }

        $token = $user->createToken('mytoken')->plainTextToken;
        $response = [
            'user' =>$user,
            'token' => $token
        ];

        return response($response, 201);
    }

    //Logout
    public function logout(Request $request){
        auth()->user()->tokens()->delete();
        return ['message'=>'Logged out'];
    }
}
