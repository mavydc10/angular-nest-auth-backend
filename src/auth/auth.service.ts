import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { IsEmail } from 'class-validator';

import { CreateUserDto,LoginDto,RegisterUserDto,UpdateAuthDto } from './dto';
import * as bcrypstjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayLoad } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jswtService: JwtService,
    ){}


  async create(createUserDto: CreateUserDto) :Promise<User>{
    console.log(createUserDto);

    //const newUser = new this.userModel(createUserDto);
    //return newUser.save();

    try{

      const {password, ...userData} = createUserDto;

      const newUser = new this.userModel({
        password: bcrypstjs.hashSync(password,10),
        ...userData
      });

        //1-encriptar contraseña

        //2-guardar usuario
    
        //3-generar jwt
        
      await newUser.save();

      const {password:_, ...user} = newUser.toJSON();

      return user;

    }
    catch(error){
      if (error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Something terasdsadrrible happen!!')
    }
  }

  async register(registerDto: RegisterUserDto):Promise<LoginResponse>{

    const user = await this.create(registerDto);
    console.log(user);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id})
    }
  }



  async login(loginDto: LoginDto):Promise<LoginResponse>{

      const { email, password } = loginDto;

      const user = await this.userModel.findOne({email});

      if (!user){
        throw new UnauthorizedException('Not valid credentisals - email');
      }

      if (!bcrypstjs.compareSync(password, user.password)){
        throw new UnauthorizedException('Not valid credentisals paswor');
      }

      const { password:_, ...rest} = user.toJSON();

      return {
        user: rest,
        token: this.getJwtToken({id:user.id}),
      };
  }


  findAll():Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id:string){
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();
    return rest;
  }


  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payLoad: JwtPayLoad){
    const token = this.jswtService.sign(payLoad);
    return token;
  }
}
