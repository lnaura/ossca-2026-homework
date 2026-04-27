# 2026 OSSCA 체험형 Git 활용 및 Cilium 과제

## 공통사항
1. user space에서 작동되는 코드는 반드시 Go로 작성해야하며, kernel space에서 작동되는 코드는 반드시 C로 작성해야 합니다.
2. 과제 제출 시 각 주차별 디렉토리에 본인의 github 계정 id로 디렉토리를 생성해야 합니다.
3. 제출한 디렉토리 내부에는 Makefile이 존재해야합니다.
4. make build를 통해 정상적으로 build를 수행 할 수 있어야 합니다.
5. build를 통해 생성된 결과물은 app이라는 이름을 가져야 합니다.