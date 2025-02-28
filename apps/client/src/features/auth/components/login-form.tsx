import * as z from "zod";
import { useForm, zodResolver } from "@mantine/form";
import useAuth from "@/features/auth/hooks/use-auth";
import { ILogin, IOIDCConfig } from "@/features/auth/types/auth.types";
import {
  Container,
  Title,
  TextInput,
  Button,
  PasswordInput,
  Box,
  Anchor,
} from "@mantine/core";
import classes from "./auth.module.css";
import { useRedirectIfAuthenticated } from "@/features/auth/hooks/use-redirect-if-authenticated.ts";
import { Link, useNavigate } from "react-router-dom";
import APP_ROUTE from "@/lib/app-route.ts";
import { useTranslation } from "react-i18next";

const formSchema = z.object({
  email: z
    .string()
    .min(1, { message: "email is required" })
    .email({ message: "Invalid email address" }),
  password: z.string().min(1, { message: "Password is required" }),
});

export function LoginForm() {
  const { t } = useTranslation();
  const { signIn, isLoading } = useAuth();

  const [buttonName, setButtonName] = React.useState<string>("Login with OIDC");
  const [oidcEnabled, setOidcEnabled] = React.useState<boolean>(false);

  useRedirectIfAuthenticated();

  useEffect(() => {
    const fetchConfig = async () => {
      const response = await api.get<IOIDCConfig>("/auth/oidc-public-config");

      setButtonName(response.data.buttonName);
      setOidcEnabled(response.data.enabled);
    };

    fetchConfig();
  });

  const form = useForm<ILogin>({
    validate: zodResolver(formSchema),
    initialValues: {
      email: "",
      password: "",
    },
  });

  async function onSubmit(data: ILogin) {
    await signIn(data);
  }

  async function loginWithOAuth() {
    window.location.href = "/api/auth/oauth-redirect";
  }

  return (
    <Container size={420} my={40} className={classes.container}>
      <Box p="xl" mt={200}>
        <Title order={2} ta="center" fw={500} mb="md">
          {t("Login")}
        </Title>

        <form onSubmit={form.onSubmit(onSubmit)}>
          <TextInput
            id="email"
            type="email"
            label={t("Email")}
            placeholder="email@example.com"
            variant="filled"
            {...form.getInputProps("email")}
          />

          <PasswordInput
            label={t("Password")}
            placeholder={t("Your password")}
            variant="filled"
            mt="md"
            {...form.getInputProps("password")}
          />

          <Button type="submit" fullWidth mt="xl" loading={isLoading}>
            {t("Sign In")}
          </Button>
          {oidcEnabled && (
            <Button
              onClick={loginWithOAuth}
              hidden={!oidcEnabled}
              fullWidth
              mt="sm"
            >
              Login with {buttonName}
            </Button>
          )}
        </form>

        <Anchor
          to={APP_ROUTE.AUTH.FORGOT_PASSWORD}
          component={Link}
          underline="never"
          size="sm"
        >
          {t("Forgot your password?")}
        </Anchor>
      </Box>
    </Container>
  );
}
