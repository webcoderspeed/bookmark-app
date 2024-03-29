import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import * as argon2 from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDTO) {
    try {
      // generate the password

      const hash = await argon2.hash(dto.password);

      // save the new user in the db

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
      });

      delete user.password;

      // return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credientail Exists!');
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDTO) {
    //  find the user by email

    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if the user does not exists throw exception
    if (!user) throw new ForbiddenException('Credential Incorrect!');

    // compare password
    const matchedPassword = await argon2.verify(user.password, dto.password);

    // if password incorrect throw exception
    if (!matchedPassword) throw new ForbiddenException('Credential Incorrect!');

    // send back the user
    delete user.password;

    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string) {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });

    return {
      access_token: token,
    };
  }
}
