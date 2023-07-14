const Joi = require('joi'); // joi 모듈을 가져와서 Joi변수에 할당
const { user } = require('./message.json'); // message.json 파일에서 User를 가져옴

const userValidation = {
  //userValidation에 signInValidation, signUpValidation,editPasswordValidation 를 담음

  signInValidation: async (req, res, next) => {
    // 요청, 응답 및 미들웨어 체인의 다음 단계로 제어를 전달
    const body = req.body; // 요청의 본문(body)을 body 변수에 할당
    const schema = Joi.object().keys({
      //Joi.object().keys({ ... })를 사용하여 검증 스키마를 생성. 이 스키마는 email과 password라는 두 개의 필드를 가진 객체를 기대.
      email: Joi.string()
        .empty()
        .max(30)
        .regex(/^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$/i)
        .required()
        .messages(user.email),
      password: Joi.string()
        .empty()
        .min(8)
        .max(20)
        .regex(/^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+])/)
        .required()
        .messages(user.password),
    });

    try {
      await schema.validateAsync(body);
    } catch (err) {
      return res.status(412).json({ message: err.message });
    }

    next();
  },
  signUpValidation: async (req, res, next) => {
    const body = req.body;
    const schema = Joi.object().keys({
      email: Joi.string()
        .empty()
        .max(30)
        .regex(/^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$/i)
        .required()
        .messages(user.email),
      name: Joi.string()
        .empty()
        .regex(/^[가-힣a-zA-Z]+$/)
        .required()
        .messages(user.name),
      password: Joi.string()
        .empty()
        .min(8)
        .max(20)
        .regex(/^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+])/)
        .required()
        .messages(user.password),
      confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages(user.confirmPassword),
    });

    try {
      await schema.validateAsync(body);
    } catch (err) {
      return res.status(412).json({ message: err.message });
    }

    next();
  }, //currentPassword, editPassword, editConfirmPassword
  editPasswordValidation: async (req, res, next) => {
    const body = req.body;
    const schema = Joi.object().keys({
      currentPassword: Joi.string()
        .empty()
        .min(8)
        .max(20)
        .regex(/^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+])/)
        .required()
        .messages(user.currentPassword),
      editPassword: Joi.string()
        .empty()
        .min(8)
        .max(20)
        .regex(/^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+])/)
        .required()
        .disallow(Joi.ref('currentPassword'))
        .messages(user.editPassword),
      editConfirmPassword: Joi.string().valid(Joi.ref('editPassword')).required().messages(user.editConfirmPassword),
    });

    try {
      await schema.validateAsync(body);
    } catch (err) {
      console.log(err);
      return res.status(412).json({ message: err.message });
    }

    next();
  },
};

module.exports = userValidation;
