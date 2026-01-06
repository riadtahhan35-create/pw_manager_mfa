from pydantic import BaseModel, Field
class FaceTemplateRegisterRequest(BaseModel):
    username: str = Field(..., min_length=1)
    face_template_enc_b64: str = Field(..., min_length=10)
class FaceTemplateResponse(BaseModel):
    username: str
    face_template_enc_b64: str