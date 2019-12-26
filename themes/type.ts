/**
 * @typedef {import("express").Response} Response
 * @typedef {import("express").Request} Request
 * @typedef {import("express").NextFunction} NextFunction
 * @typedef {typeof import("../services/user-service").UserService} UserServices
 * @typedef {typeof import("resume-app").AppRequest} AppRequest
 * @typedef {typeof import("resume-app").RegisterCredentials} Credentials
 * @typedef {typeof import("resume-app").LoginCredentials} LoginCredentials
 * @typedef {typeof import("resume-app").RegisterCredentials} Credentials
 *
 */
import { NextFunction, Request, Response } from "express";
import { BAD_REQUEST, getStatusText, INTERNAL_SERVER_ERROR, NOT_FOUND, OK } from "http-status-codes";
import { LoginCredentials, TokenModel, UserRegister } from "resume-app";
import { encriptPassword, isEqualsPassword } from "../utils/encripter";
import { logger } from "../utils/logger";
import { createToken } from "../utils/passport";
import { apiResponse, failedResponse, successResponse } from "../utils/response";
import { UserService } from "./../services/user-service";

/**
 * User controller
 * @class UserController
 * @public
 * @author Ernesto Jara Olveda
 */
export class UserController {
    private userService: UserService;
    /**
     * @description Creates an instance of user controller.
     *
     * @param {UserServices} userService
     */
    public constructor (userService: UserService) {
        /** @property {TypesUserService} UserController#userService - instance of user service. */
        this.userService = userService;
        this.register = this.register.bind(this);
        this.getAllUsers = this.getAllUsers.bind(this);
        this.login = this.login.bind(this);
    }

    /**
     * Registers a new user into the system.
     *
     * @public
     * @Get
     * @async
     * @method UserController#register
     * @param {TypesAppRequest<TypesCredentials>} req - `HTTP` request object.
     * @param {TypesResponse} res - `HTTP` response object.
     * @param {TypesNextFunction} next - `middleware` pipe.
     * @returns {Promise<TypesResponse>} 201 if the user is created successfully
     */
    public async register(
        req: Request,
        res: Response,
        next: NextFunction
    ): Promise<Response> {
        try {
            const user = <UserRegister>req.body;
            logger.info("register");

            const isEmailAlready = await this.userService.getUserByEmail(
                user.email
            );
            if (isEmailAlready !== null) {
                logger.warn(`the email ${isEmailAlready.email} already exists`);
                return apiResponse(
                    res,
                    failedResponse("email already exists"),
                    BAD_REQUEST
                );
            }

            user.password = await encriptPassword(user.password, 10);

            const success = await this.userService.save(user);

            return apiResponse(
                res,
                successResponse(getStatusText(success)),
                success
            );
        } catch (error) {
            logger.error("error while register", { meta: { ...error } });
            return apiResponse(
                res,
                failedResponse(getStatusText(INTERNAL_SERVER_ERROR)),
                INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Logins user controller.
     *
     * @async
     * @POST
     * @method
     * @name UserController#login
     * @param {AppRequest<LoginCredentials>} req - `HTTP` request object.
     * @param {TypesResponse} res - `HTTP` response object.
     * @param {TypesNextFunction} next - `middleware` pipe.
     * @returns {Promise<TypesResponse>} a promise of EndPointResponse
     */
    public async login(req: Request, res: Response, next: NextFunction): Promise<Response> {
        try {
            logger.info(`login ${req.body.email}`);
            const loginCredentials = <LoginCredentials>req.body;

            const stored = await this.userService.getUserByEmail(
                loginCredentials.email
            );

            if (stored === null) {
                logger.warn(`user not found: ${loginCredentials.email}`);

                return apiResponse(
                    res,
                    failedResponse("user not found"),
                    NOT_FOUND
                );
            }

            const samePassword = await isEqualsPassword(
                stored.password,
                loginCredentials.password
            );

            if (!samePassword) {
                logger.warn("wrong password");
                return apiResponse(
                    res,
                    failedResponse("user not found"),
                    NOT_FOUND
                );
            }

            const toSend: TokenModel = {
                id: stored.id,
                email: stored.email,
                name: stored.name,
                middleName: stored.middleName,
                lastName: stored.lastName,
                secondLastName: stored.secondLastName,
            };

            const token = createToken(toSend);

            return apiResponse(
                res,
                successResponse({
                    ...toSend,
                    token: `Bearer ${token}`,
                }),
                OK
            );
        } catch (error) {
            logger.error("error while register", { meta: { ...error } });
            return apiResponse(
                res,
                failedResponse(getStatusText(INTERNAL_SERVER_ERROR)),
                INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Logins user controller.
     *
     * @async
     * @public
     * @method
     * @name UserController#login
     * @param {TypesRequest<TypesLoginCredentials>} req - `HTTP` request object.
     * @param {TypesResponse} res - `HTTP` response object.
     * @param {TypesNextFunction} next - `middleware` pipe.
     * @returns {Promise<TypesResponse>} a promise of EndPointResponse
     */
    public async getAllUsers(
        req: Request,
        res: Response,
        next: NextFunction
    ): Promise<Response> {
        logger.info("getAllUsers");
        try {
            const users = await this.userService.getAllUsers();

            return apiResponse(res, successResponse(users), OK);
        } catch (error) {
            logger.error("error while getting all users", {
                meta: { ...error },
            });
            return apiResponse(
                res,
                failedResponse(getStatusText(INTERNAL_SERVER_ERROR)),
                INTERNAL_SERVER_ERROR
            );
        }
    }
}
