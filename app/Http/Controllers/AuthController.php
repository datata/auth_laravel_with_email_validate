<?php

namespace App\Http\Controllers;

use App\Mail\ExampleMail;
use App\Models\User;
use Error;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    const ROLE_ADMIN = 2;

    public function register(Request $request)
    {
        try {
            Log::info("Register");

            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:100',
                'email' => 'required|string|email|max:100|unique:users',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json(
                    [
                        "success" => false,
                        "error" => $validator->errors()
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }

            $user = User::create([
                'name' => $request->get('name'),
                'email' => $request->get('email'),
                'password' => bcrypt($request->password),
                'hash' => md5(rand(0, 1000))
            ]);

            $user->roles()->attach(self::ROLE_ADMIN);

            $token = JWTAuth::fromUser($user);

            Mail::to('dani@dani.com')->send(new ExampleMail());

            return response()->json(
                [
                    "success" => true,
                    "user" => $user,
                    "token" => $token
                ],
                Response::HTTP_CREATED
            );
        } catch (\Exception $exception) {
            Log::error('Error register user -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be registered'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function login(Request $request)
    {
        try {
            Log::info('Login');

            $input = $request->only('email', 'password');
            $jwtToken = null;

            if (!$jwtToken = JWTAuth::attempt($input)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid Email or Password',
                ], Response::HTTP_UNAUTHORIZED);
            }

            return response()->json([
                'success' => true,
                'token' => $jwtToken,
            ]);
        } catch (\Exception $exception) {
            Log::error('Error register user -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be registered'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function me()
    {
        Log::info('Profile');

        return response()->json(
            [
                "success" => true,
                "message" => "User data",
                "data" => auth()->user()
            ]
        );
    }

    public function logout(Request $request)
    {
        $this->validate($request, ['token' => 'required']);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (\Exception $exception) {
            Log::error('Error logout -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot be logged out'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    public function activeUser(Request $request)
    {
        try {
            Log::info('Validating account.');

            $user = User::query()
                ->where('hash', $request->query('hash'))
                ->where('email', $request->query('email'))
                ->where('is_active', false)
                ->firstOrFail();
            ;
            $user->is_active = true;
            $user->save();

            return response()->json([
                'success' => true,
                'message' => 'User actived successfully'
            ], 400);
        } catch (\Exception $exception) {
            Log::error('Error validating account -> ' . $exception->getMessage());

            return response()->json(
                [
                    'success' => false,
                    'message' => 'Sorry, the user cannot actived'
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }
}
